pipeline {
    agent {
        dockerfile { filename 'Dockerfile' }
    }

    parameters {
        choice(name: 'ENV_TYPE', choices: ['DEV', 'HML', 'PRD'], description: 'Ambiente')
        string(name: 'AWS_REGION', defaultValue: 'us-east-1', description: 'Região AWS')
        
        // Campos Obrigatórios - O usuário DEVE preencher
        string(name: 'CLUSTER_SOURCE_NAME', description: 'Cluster de ORIGEM')
        string(name: 'CLUSTER_DEST_NAME', description: 'Cluster de DESTINO')
        string(name: 'VELERO_BUCKET_NAME', description: 'Nome do Bucket S3 (Existente)')
        string(name: 'VELERO_ROLE_ARN', description: 'ARN da Role IAM (Existente)')
        
        // Opcionais
        string(name: 'ISTIO_SYNC_MODE', defaultValue: 'all', description: "'all', 'none' ou lista separada por vírgula")
        booleanParam(name: 'CLEANUP_ENABLED', defaultValue: false, description: 'Limpeza prévia do Velero?')
        booleanParam(name: 'SKIP_RESTORE', defaultValue: false, description: 'Pular restore? (Apenas Backup)')
    }

    environment {
        // Plugin de Credenciais injeta AWS_ACCESS_KEY_ID e AWS_SECRET_ACCESS_KEY
        AWS_CREDS = credentials('aws-migration-creds')
    }

    stages {
        stage('Executar Migração') {
            steps {
                script {
                    // Passa credenciais para o script
                    withCredentials([usernamePassword(credentialsId: 'aws-migration-creds', usernameVariable: 'AWS_ACCESS_KEY_ID', passwordVariable: 'AWS_SECRET_ACCESS_KEY')]) {
                        sh 'python3 migracao_jenkins.py'
                    }
                }
            }
        }
    }
}
