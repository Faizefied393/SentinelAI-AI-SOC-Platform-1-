FROM python:3.12-slim
WORKDIR /project
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY sample_data ./sample_data
RUN mkdir -p /project/data
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
