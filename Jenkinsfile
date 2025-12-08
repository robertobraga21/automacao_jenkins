pipeline {
    agent {
        dockerfile { filename 'Dockerfile' }
    }

    parameters {
        choice(name: 'OPERATION_MODE', choices: ['FULL_MIGRATION', 'BACKUP_ONLY', 'RESTORE_ONLY'], description: 'Selecione o tipo de operação')
        string(name: 'AWS_REGION', defaultValue: 'us-east-1', description: 'Região AWS')
        
        string(name: 'CLUSTER_SOURCE_NAME', defaultValue: '', description: 'Cluster ORIGEM (Obrigatório para FULL e BACKUP)')
        string(name: 'CLUSTER_DEST_NAME', defaultValue: '', description: 'Cluster DESTINO (Obrigatório para FULL e RESTORE)')
        
        string(name: 'BACKUP_NAME_TO_RESTORE', defaultValue: '', description: 'Nome do Backup para restaurar (Apenas p/ RESTORE_ONLY)')
        
        string(name: 'VELERO_BUCKET_NAME', description: 'Nome do Bucket S3')
        string(name: 'VELERO_ROLE_ARN', description: 'ARN da Role IAM do Velero')
        
        string(name: 'ISTIO_SYNC_MODE', defaultValue: 'all', description: 'Istio Sync (all/none)')
        booleanParam(name: 'CLEANUP_ENABLED', defaultValue: false, description: 'Limpeza prévia do Velero?')
    }

    environment {
        AWS_ACCESS_KEY_ID = credentials('aws-migration-creds-usr')
        AWS_SECRET_ACCESS_KEY = credentials('aws-migration-creds-psw')
    }

    stages {
        stage('Executar Migração') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'aws-migration-creds', usernameVariable: 'AWS_ACCESS_KEY_ID', passwordVariable: 'AWS_SECRET_ACCESS_KEY')]) {
                    sh 'python3 migracao_jenkins.py'
                }
            }
        }
    }
}