import subprocess
import time
import sys
import os
import json
import boto3
from botocore.exceptions import ClientError
from kubernetes import client, config as k8s_config

# --- CONFIGURAÇÃO GLOBAL ---
CONFIG = {}

SYSTEM_NAMESPACES = [
    "default", "kube-system", "kube-public", "kube-node-lease", 
    "velero", "amazon-cloudwatch", "aws-observability", "istio-system", "istio-ingress", "cert-manager", "monitoring",
    "cattle-system", "cattle-fleet-system"
]

EXCLUDE_RESOURCES = "pods,replicasets,endpoints,endpointslices"

VELERO_IAM_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeVolumes", "ec2:DescribeSnapshots", "ec2:CreateTags",
                "ec2:CreateVolume", "ec2:CreateSnapshot", "ec2:DeleteSnapshot"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject", "s3:DeleteObject", "s3:PutObject",
                "s3:AbortMultipartUpload", "s3:ListBucket"
            ],
            "Resource": "*" 
        }
    ]
}

# --- 0. HELPERS (STRICT HEADLESS) ---
def get_required_env(var_name):
    val = os.getenv(var_name)
    if not val:
        print(f"⛔ ERRO CRÍTICO: Variável de ambiente '{var_name}' não definida.")
        sys.exit(1)
    return val.strip()

def run_shell(cmd, ignore_error=False, quiet=False):
    if not quiet: print(f"   [CMD] {cmd}")
    try: 
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL if quiet else None)
        return True
    except: 
        if not ignore_error: 
            print(f"❌ Falha na execução do comando.")
            sys.exit(1)
        return False

# --- 1. SETUP ---
def load_config():
    print("\n🚀 --- Migração EKS V46 (Helm Repo Fix) ---")
    
    CONFIG['env'] = get_required_env("ENV_TYPE").upper()
    CONFIG['region'] = get_required_env("AWS_REGION")
    CONFIG['cluster_src'] = get_required_env("CLUSTER_SOURCE_NAME")
    CONFIG['cluster_dst'] = get_required_env("CLUSTER_DEST_NAME")
    CONFIG['bucket_name'] = get_required_env("VELERO_BUCKET_NAME")
    CONFIG['role_arn'] = get_required_env("VELERO_ROLE_ARN")
    
    CONFIG['istio_sync_mode'] = os.getenv("ISTIO_SYNC_MODE", "all").lower()
    CONFIG['cleanup'] = os.getenv("CLEANUP_ENABLED", "false").lower() == 'true'
    CONFIG['skip_restore'] = os.getenv("SKIP_RESTORE", "false").lower() == 'true'

    print(f"   ℹ️  Ambiente: {CONFIG['env']}")
    print(f"   ℹ️  Região: {CONFIG['region']}")
    print(f"   ℹ️  Origem: {CONFIG['cluster_src']}")
    print(f"   ℹ️  Destino: {CONFIG['cluster_dst']}")

def get_aws_session():
    return boto3.Session(region_name=CONFIG['region'])

# --- 2. VALIDAÇÃO DE RECURSOS ---
def validate_bucket(bucket_name):
    print(f"\n📦 Validando Bucket S3: {bucket_name}")
    s3 = get_aws_session().client('s3')
    try:
        s3.head_bucket(Bucket=bucket_name)
        print(f"   ✅ Bucket acessível.")
    except ClientError as e:
        print(f"   ⛔ ERRO: Bucket inacessível ou inexistente: {e}")
        sys.exit(1)

def extract_and_validate_role(role_arn):
    print(f"\n👤 Validando Role IAM: {role_arn}")
    try:
        role_name = role_arn.split('/')[-1]
        iam = get_aws_session().client('iam')
        iam.get_role(RoleName=role_name)
        print(f"   ✅ Role válida.")
        return role_name
    except Exception as e:
        print(f"   ⛔ ERRO: Role inválida: {e}")
        sys.exit(1)

# --- 3. CONTEXTO K8S ---
def setup_kube_context(cluster_name):
    print(f"   🔍 Configurando kubeconfig para '{cluster_name}'...")
    try:
        cmd = f"aws eks update-kubeconfig --name {cluster_name} --region {CONFIG['region']}"
        run_shell(cmd, quiet=True)
        eks = get_aws_session().client('eks')
        return eks.describe_cluster(name=cluster_name)['cluster']['arn']
    except Exception as e:
        print(f"      ⛔ Erro ao configurar cluster: {e}")
        sys.exit(1)

# --- 4. PREPARAÇÃO E CONFIG ---
def generate_velero_values(bucket, role_arn, region):
    print(f"\n📝 Gerando 'values.yaml'...")
    yaml_content = f"""configuration:
  backupStorageLocation:
    - bucket: {bucket}
      provider: aws
      config:
        region: {region}
  volumeSnapshotLocation:
    - provider: aws
      config:
        region: {region}
credentials:
  useSecret: false
initContainers:
  - name: velero-plugin-for-aws
    image: velero/velero-plugin-for-aws:v1.9.0
    volumeMounts:
      - mountPath: /target
        name: plugins
serviceAccount:
  server:
    create: true
    name: velero-server
    annotations:
      eks.amazonaws.com/role-arn: {role_arn}
kubectl:
  image:
    repository: docker.io/bitnamilegacy/kubectl
upgradeCRDs: false
cleanUpCRDs: false
"""
    try:
        with open("values.yaml", "w") as f: f.write(yaml_content)
    except Exception as e: print(f"❌ Erro values.yaml: {e}"); sys.exit(1)

def get_cluster_oidc(name):
    return get_aws_session().client('eks').describe_cluster(name=name)['cluster']['identity']['oidc']['issuer'].replace("https://", "")

def ensure_role_permissions(role_name):
    print(f"   🛡️  Garantindo permissões na role '{role_name}'...")
    iam = get_aws_session().client('iam')
    try:
        iam.put_role_policy(RoleName=role_name, PolicyName="VeleroPerms", PolicyDocument=json.dumps(VELERO_IAM_POLICY))
    except Exception as e: print(f"      ⚠️  Falha ao aplicar permissões: {e}")

def update_trust_policy(role_name, oidc, ns, sa):
    iam = get_aws_session().client('iam'); sts = get_aws_session().client('sts')
    acc = sts.get_caller_identity()["Account"]
    oidc_arn = f"arn:aws:iam::{acc}:oidc-provider/{oidc}"
    try:
        role_data = iam.get_role(RoleName=role_name)
        pol = role_data['Role']['AssumeRolePolicyDocument']
        for s in pol['Statement']:
            if s.get('Principal', {}).get('Federated') == oidc_arn:
                cond = s.get('Condition', {}).get('StringEquals', {})
                for k,v in cond.items():
                    if f"{oidc}:sub" in k and v == f"system:serviceaccount:{ns}:{sa}": return False
        print(f"   ➕ Atualizando Trust: OIDC -> Role '{role_name}'")
        pol['Statement'].append({
            "Effect": "Allow", "Principal": {"Federated": oidc_arn}, "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringEquals": {f"{oidc}:sub": f"system:serviceaccount:{ns}:{sa}"}}
        })
        iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=json.dumps(pol))
        return True
    except Exception as e: 
        print(f"   ⚠️  Aviso: Falha ao atualizar Trust Policy: {e}")
        return False

def run_pre_flight_irsa(ctx, dest_oidc):
    print(f"\n🕵️  [IRSA] Scan de Aplicações em {ctx}...")
    try:
        k8s_config.load_kube_config(config_file=os.environ["KUBECONFIG"], context=ctx)
        v1 = client.CoreV1Api()
    except Exception as e:
        print(f"   ⛔ Erro carregando Kubeconfig: {e}")
        sys.exit(1)

    try:
        items = v1.list_service_account_for_all_namespaces().items
    except Exception as e:
        print(f"   ⛔ Erro listando ServiceAccounts: {e}")
        return

    cnt = 0
    for sa in items:
        ns = sa.metadata.namespace
        if ns in SYSTEM_NAMESPACES: continue
        arn = (sa.metadata.annotations or {}).get('eks.amazonaws.com/role-arn')
        if arn:
            r_name = arn.split("/")[-1]
            if r_name == CONFIG['role_name'] or "aws-service-role" in r_name: continue
            if update_trust_policy(r_name, dest_oidc, ns, sa.metadata.name): 
                cnt += 1; time.sleep(0.2)
    print(f"✅ {cnt} apps atualizadas.")

# --- 5. ISTIO SYNC (HEADLESS) ---
def sanitize_k8s_object(obj):
    if 'metadata' in obj:
        for field in ['resourceVersion', 'uid', 'creationTimestamp', 'generation', 'ownerReferences', 'managedFields']:
            obj['metadata'].pop(field, None)
        annotations = obj['metadata'].get('annotations', {})
        annotations.pop('kubectl.kubernetes.io/last-applied-configuration', None)
        obj['metadata']['annotations'] = annotations
    obj.pop('status', None)
    return obj

def sync_istio_resources(src_ctx, dst_ctx):
    mode = CONFIG['istio_sync_mode']
    if mode == 'none': return

    print(f"\n🕸️  [ISTIO] Sincronizando (Mode: {mode})...")
    k8s_config.load_kube_config(config_file=os.environ["KUBECONFIG"], context=src_ctx)
    custom_api_src = client.CustomObjectsApi()
    
    ns_ignore_istio = [ns for ns in SYSTEM_NAMESPACES if ns != "istio-system"]
    group = "networking.istio.io"; version = "v1beta1"; plural = "virtualservices"
    
    candidates = []
    try:
        resp = custom_api_src.list_cluster_custom_object(group, version, plural)
        items = [i for i in resp.get('items', []) if i['metadata']['namespace'] not in ns_ignore_istio]
        
        if mode == 'all':
            candidates = [sanitize_k8s_object(i) for i in items]
        else:
            target_names = [n.strip() for n in mode.split(',')]
            candidates = [sanitize_k8s_object(i) for i in items if i['metadata']['name'] in target_names]
    except Exception as e: print(f"    ⚠️  Erro leitura Istio: {e}"); return

    if not candidates: print("    ℹ️  Nada para sincronizar."); return

    print(f"    📤 Aplicando {len(candidates)} VSs no Destino...")
    k8s_config.load_kube_config(config_file=os.environ["KUBECONFIG"], context=dst_ctx)
    custom_api_dst = client.CustomObjectsApi()
    
    for body in candidates:
        ns = body['metadata']['namespace']; name = body['metadata']['name']
        try: client.CoreV1Api().create_namespace(client.V1Namespace(metadata=client.V1ObjectMeta(name=ns)))
        except: pass
        try:
            custom_api_dst.create_namespaced_custom_object(group, version, ns, plural, body)
            print(f"    ✅ Criado: {ns}/{name}")
        except client.exceptions.ApiException as e:
            if e.status == 409:
                try:
                    exist = custom_api_dst.get_namespaced_custom_object(group, version, ns, plural, name)
                    body['metadata']['resourceVersion'] = exist['metadata']['resourceVersion']
                    custom_api_dst.replace_namespaced_custom_object(group, version, ns, plural, name, body)
                    print(f"    🔄 Atualizado: {ns}/{name}")
                except: print(f"    ❌ Falha update: {name}")
            else: print(f"    ❌ Falha create: {name}")

# --- 6. VELERO CONTROL ---
def wait_for_backup_sync(bk):
    print(f"⏳ Aguardando sync do backup '{bk}' no destino...")
    for i in range(24):
        res = subprocess.run(f"velero backup describe {bk}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode == 0: print(f"   ✅ Backup disponível!"); return True
        time.sleep(5)
    print("\n❌ Timeout sync."); return False

def cleanup_velero(context):
    print(f"🧹 [CLEANUP] Limpando {context}...")
    run_shell(f"kubectl config use-context {context}", quiet=True)
    run_shell("helm uninstall velero -n velero", ignore_error=True, quiet=True)
    run_shell("kubectl delete ns velero --timeout=30s --wait=false", ignore_error=True, quiet=True)
    time.sleep(10)

def install_velero(context):
    if CONFIG['cleanup']: cleanup_velero(context)
    print(f"⚓ [{context}] Instalando Velero...")
    run_shell(f"kubectl config use-context {context}", quiet=True)
    run_shell("kubectl create ns velero --dry-run=client -o yaml | kubectl apply -f -", quiet=True)
    
    # --- CORREÇÃO: ADICIONA REPO ANTES DE INSTALAR ---
    run_shell("helm repo add vmware-tanzu https://vmware-tanzu.github.io/helm-charts", quiet=True)
    run_shell("helm repo update", quiet=True)
    # ------------------------------------------------
    
    cmd = f"helm upgrade --install velero vmware-tanzu/velero --namespace velero -f values.yaml --reset-values --wait"
    run_shell(cmd, quiet=True)
    run_shell("kubectl rollout restart deployment velero -n velero", quiet=True)

# --- MAIN ---
def main():
    # Fix para permissões no Jenkins
    os.environ["HOME"] = os.getcwd()
    os.environ["KUBECONFIG"] = os.path.join(os.getcwd(), "kube_config")
    
    load_config()
    
    validate_bucket(CONFIG['bucket_name'])
    CONFIG['role_name'] = extract_and_validate_role(CONFIG['role_arn'])
    ensure_role_permissions(CONFIG['role_name'])
    generate_velero_values(CONFIG['bucket_name'], CONFIG['role_arn'], CONFIG['region'])

    ctx_src = setup_kube_context(CONFIG['cluster_src'])
    ctx_dst = setup_kube_context(CONFIG['cluster_dst'])

    print("\n☁️  Configurando OIDCs...")
    oidc_src = get_cluster_oidc(CONFIG['cluster_src'])
    oidc_dst = get_cluster_oidc(CONFIG['cluster_dst'])
    update_trust_policy(CONFIG['role_name'], oidc_src, "velero", "velero-server")
    update_trust_policy(CONFIG['role_name'], oidc_dst, "velero", "velero-server")
    
    run_pre_flight_irsa(ctx_src, oidc_dst)
    sync_istio_resources(ctx_src, ctx_dst)

    bk = f"migracao-{CONFIG['env'].lower()}-{int(time.time())}"

    print(f"\n--- 🚀 FASE ORIGEM ---")
    install_velero(ctx_src)
    print(f"💾 Criando Backup: {bk}")
    
    try:
        run_shell(f"velero backup create {bk} --exclude-namespaces {','.join(SYSTEM_NAMESPACES)} --exclude-resources {EXCLUDE_RESOURCES} --wait")
        print("⏳ Aguardando 60s para consolidação do Snapshot na AWS...")
        time.sleep(60) 
    except SystemExit:
        print("❌ Backup falhou. Abortando Pipeline.")
        sys.exit(1)

    if CONFIG['skip_restore']:
        print("\n⏭️  SKIP_RESTORE=true. Backup criado, restore pulado.")
        sys.exit(0)

    print(f"\n--- 🛬 FASE DESTINO ---")
    install_velero(ctx_dst)
    
    if wait_for_backup_sync(bk):
        print(f"♻️  Iniciando Restore...")
        run_shell(f"velero restore create --from-backup {bk} --existing-resource-policy update --exclude-resources {EXCLUDE_RESOURCES} --wait")
        print("\n🎉 Migração realizada com sucesso!")
    else:
        print("\n⛔ Restore abortado (Timeout sync).")
        sys.exit(1)

if __name__ == "__main__":
    main()