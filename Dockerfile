FROM python:3.9-slim
RUN apt-get update && apt-get install -y curl unzip git jq
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && unzip awscliv2.zip && ./aws/install
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
RUN curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
RUN curl -L https://github.com/vmware-tanzu/velero/releases/download/v1.12.0/velero-v1.12.0-linux-amd64.tar.gz -o velero.tar.gz && tar -zxvf velero.tar.gz && mv velero-v1.12.0-linux-amd64/velero /usr/local/bin/velero
RUN pip install boto3 kubernetes requests
WORKDIR /app
