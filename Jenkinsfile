pipeline {
    agent {
        dockerfile {
            filename 'Dockerfile'
        }
    }

    parameters {
        choice(name: 'OPERATION_MODE', choices: ['FULL_MIGRATION', 'BACKUP_ONLY', 'RESTORE_ONLY'], description: 'Selecione o tipo de operação')
        string(name: 'AWS_REGION', defaultValue: 'us-east-1', description: 'Região AWS')
        
        string(name: 'CLUSTER_SOURCE_NAME', defaultValue: '', description: 'Nome Exato do Cluster ORIGEM (Para FULL e BACKUP)')
        string(name: 'CLUSTER_DEST_NAME', defaultValue: '', description: 'Nome Exato do Cluster DESTINO (Para FULL e RESTORE)')
        
        string(name: 'BACKUP_NAME_TO_RESTORE', defaultValue: '', description: 'Nome do Backup para restaurar (Apenas p/ RESTORE_ONLY)')
        
        string(name: 'VELERO_BUCKET_NAME', description: 'Nome do Bucket S3 (Existente)')
        string(name: 'VELERO_ROLE_ARN', description: 'ARN da Role IAM (Existente)')
        
        string(name: 'ISTIO_SYNC_MODE', defaultValue: 'all', description: "'all', 'none' ou lista separada por vírgula")
        booleanParam(name: 'CLEANUP_ENABLED', defaultValue: false, description: 'Limpeza prévia do Velero?')
        booleanParam(name: 'SKIP_RESTORE', defaultValue: false, description: 'Pular restore? (Apenas Backup)')
    }

    stages {
        stage('Executar Migração') {
            steps {
                // AQUI ESTÁ A CORREÇÃO:
                // Mapeia o Username para a variavel de Access Key
                // Mapeia o Password para a variavel de Secret Key
                withCredentials([usernamePassword(credentialsId: 'aws-migration-creds', usernameVariable: 'AWS_ACCESS_KEY_ID', passwordVariable: 'AWS_SECRET_ACCESS_KEY')]) {
                    sh 'python3 migracao_jenkins.py'
                }
            }
        }
    }
}