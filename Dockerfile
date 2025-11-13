# Use uma imagem base oficial do Python
FROM python:3.10-slim

# Defina o diretório de trabalho no contêiner
WORKDIR /app

# Copie o arquivo de dependências
COPY requirements.txt .

# Instale as dependências
RUN pip install --no-cache-dir -r requirements.txt

# Copie o resto do código da aplicação
COPY . .

# Defina a variável de ambiente para a porta que o Railway espera
ENV PORT 8080

# Exponha a porta que o aplicativo irá rodar
EXPOSE 8080

# Comando para rodar a aplicação usando Gunicorn (servidor de produção)
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "main:app"]
