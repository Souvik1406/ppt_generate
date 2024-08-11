# Automated PPT Generation Project - TEST

## Here's a comprehensive `README.md` file for your GitHub repository, detailing the Azure Function and Logic App workflow:

# Azure Security Logs Processing and Reporting

## Overview

This repository contains an Azure Function and Logic App setup for processing security logs, generating reports, and sending notifications. The system is designed to automate the generation of monthly security reports, which are then sent to clients via email with links to downloadable reports and screenshots.

## Components

1. **Azure Function**: Processes security logs, generates reports and screenshots, and uploads them to Azure Blob Storage.
2. **Azure Logic App**: Triggers the Azure Function, checks its execution status, and sends an email with links to the generated files.

## Workflow

1. **Trigger**: The Logic App is triggered based on a schedule (monthly) or an HTTP request.
2. **Azure Function Execution**: The Azure Function processes security logs, generates a report and screenshot, and uploads these files to Blob Storage.
3. **Email Notification**: After successful execution, an email is sent to the client with links to the report and screenshot.

## Azure Function

### Purpose

The Azure Function reads security logs from Azure Blob Storage, generates a summary report and a screenshot of the data, uploads them to Blob Storage, and sends an email with these files.

### Code

```
import logging
import pandas as pd
import matplotlib.pyplot as plt
from azure.storage.blob import BlobServiceClient
from azure.functions import HttpRequest, HttpResponse
import os

# Initialize Blob Storage Client
connection_string = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
blob_service_client = BlobServiceClient.from_connection_string(connection_string)
container_name = "security-logs"

def generate_report(logs_df):
    report = logs_df.describe().to_html()  # Convert summary statistics to HTML
    return report

def create_screenshot(logs_df):
    plt.figure(figsize=(10, 6))
    logs_df.plot(kind='line')  # Example plot
    plt.title('Security Logs Over Time')
    plt.xlabel('Time')
    plt.ylabel('Value')
    screenshot_path = '/tmp/screenshot.png'
    plt.savefig(screenshot_path)
    plt.close()
    return screenshot_path

def upload_to_blob(file_path, blob_name):
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
    with open(file_path, "rb") as data:
        blob_client.upload_blob(data, overwrite=True)

def send_email_with_attachment(report_link, screenshot_link):
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.base import MIMEBase
    from email import encoders

    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = os.getenv("SMTP_PORT")
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")

    sender_email = "your-email@example.com"
    recipient_email = "client-email@example.com"
    subject = "Security Logs Report"
    body = f"""
    Dear Client,

    Please find attached the security logs report for the past month.

    Report Link: {report_link}
    Screenshot Link: {screenshot_link}

    Best regards,
    Your Company
    """

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    attachment = MIMEBase('application', 'octet-stream')
    with open('/tmp/report.html', 'rb') as file:
        attachment.set_payload(file.read())
    encoders.encode_base64(attachment)
    attachment.add_header('Content-Disposition', 'attachment; filename="report.html"')
    msg.attach(attachment)

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.login(smtp_user, smtp_password)
        server.sendmail(sender_email, recipient_email, msg.as_string())

def main(req: HttpRequest) -> HttpResponse:
    logging.info('Processing security logs...')

    blob_client = blob_service_client.get_blob_client(container=container_name, blob='security-logs.csv')
    download_stream = blob_client.download_blob()
    logs_df = pd.read_csv(download_stream)

    report = generate_report(logs_df)
    report_path = '/tmp/report.html'
    with open(report_path, 'w') as file:
        file.write(report)

    screenshot_path = create_screenshot(logs_df)

    upload_to_blob(report_path, 'reports/security-report.html')
    upload_to_blob(screenshot_path, 'screenshots/security-screenshot.png')

    report_link = f"https://{os.getenv('AZURE_STORAGE_ACCOUNT_NAME')}.blob.core.windows.net/{container_name}/reports/security-report.html"
    screenshot_link = f"https://{os.getenv('AZURE_STORAGE_ACCOUNT_NAME')}.blob.core.windows.net/{container_name}/screenshots/security-screenshot.png"

    send_email_with_attachment(report_link, screenshot_link)

    return HttpResponse("Report generated and sent via email.", status_code=200)
```

### Dependencies

Include the following in your `requirements.txt`:

```
pandas
matplotlib
azure-storage-blob
```

## Azure Logic App

### Workflow

1. **Trigger**: Configure a Recurrence trigger (monthly) or an HTTP request trigger.
2. **Action**: Call the Azure Function to process logs and generate reports.
3. **Condition**: Check the status of the Azure Function execution.
4. **Action**: Send an email with the report and screenshot links.

### Flow Diagram

```
+---------------------------------+
|             Trigger             |
|---------------------------------|
|  [Recurrence/HTTP Request]      |
|  - Trigger Function monthly      |
|  - HTTP request for on-demand    |
+---------------------------------+
                |
                v
+---------------------------------+
|      Execute Azure Function      |
|---------------------------------|
|  [Call Azure Function]           |
|  - Function: ProcessSecurityLogs |
|  - Pass required parameters      |
+---------------------------------+
                |
                v
+---------------------------------+
|   Condition: Check Function      |
|   Status                         |
|---------------------------------|
|  [Check if Execution was         |
|   successful]                    |
|  - Yes: Proceed to send email    |
|  - No: Handle failure (optional) |
+---------------------------------+
                |
          +-----+-----+
          |           |
          v           v
+----------------+   +-----------------+
|   Send Email   |   |  Failure Handling |
|----------------|   |------------------|
| [Send Email]   |   | [Optional actions] |
| - To: Client   |   | - Log error       |
| - Subject:     |   | - Notify admin    |
|   "Monthly     |   +------------------+
|   Security Logs|
|   Report"      |
| - Body:        |
|   Report and   |
|   Screenshot   |
|   links        |
+----------------+
```

## Deployment

1. **Deploy the Azure Function**: Use the Azure Portal, Visual Studio Code, or Azure CLI to deploy.
2. **Configure Environment Variables**: Set up required environment variables for Azure Storage and email settings.
3. **Create and Configure Logic App**: Set up the Logic App to automate the process based on the described workflow.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For any questions or support, please contact [Your Name](mailto:roy.thedivineacademy@gmail.com).

```

