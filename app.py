import os
from flask import Flask, request, render_template, redirect, url_for, session
from email.mime.text import MIMEText
import smtplib

app = Flask(__name__)
app.secret_key = "your_secret_key_here"  # Replace with your own secret key


def send_email(recipient, subject, body, html=False):
    """
    Sends an email using SMTP. Supports both plain text and HTML emails.
    """
    sender = "Hackmas@cybergeneration.tech"  # Replace with your email
    password = "311050Whyte2020##"   # Replace with your email password

    msg = MIMEText(body, "html" if html else "plain")  # Use HTML if specified
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = recipient

    try:
        with smtplib.SMTP("smtp.titan.email", 587) as server:  # Replace with your SMTP server
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, recipient, msg.as_string())
    except Exception as e:
        print(f"Error sending email: {e}")


@app.route('/', methods=['GET', 'POST'])
def index():
    """
    Registration page with rules and agreement.
    """
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        agree = request.form.get('agree', None)

        if full_name and agree:
            with open("participants.txt", "a") as file:
                file.write(f"{full_name}\n")

            session['progress'] = 0
            return redirect(url_for('login'))
        else:
            return render_template("index.html", error="Please enter your name and agree to the rules.")

    return render_template("index.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    SQL Injection Challenge.
    """
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        if username == "admin' --":
            session['progress'] = 1
            return redirect(url_for('hash_cracking'))
        else:
            return render_template("login.html", error="Invalid credentials. Try again!")

    return render_template("login.html")


@app.route('/hash', methods=['GET', 'POST'])
def hash_cracking():
    """
    Hash Cracking Challenge.
    """
    if session.get('progress', 0) < 1:
        return redirect(url_for('login'))

    hashes = ["e99a18c428cb38d5f260853678922e03", "5f4dcc3b5aa765d61d8327deb882cf99"]

    if request.method == 'POST':
        answer1 = request.form.get('answer1', '').strip()
        answer2 = request.form.get('answer2', '').strip()

        if answer1 == "abc123" and answer2 == "password":
            session['progress'] = 2
            return redirect(url_for('file_inclusion'))
        else:
            return render_template("hash.html", hashes=hashes, error="Incorrect answers. Try again!")

    return render_template("hash.html", hashes=hashes)


@app.route('/file_inclusion', methods=['GET', 'POST'])
def file_inclusion():
    """
    File Inclusion Challenge.
    """
    if session.get('progress', 0) < 2:
        return redirect(url_for('hash_cracking'))

    file_content = None
    error_message = None

    if request.method == 'POST':
        # If the user is viewing a file
        if "view_file" in request.form:
            file = request.form.get('file', '').strip()

            if file == "..%2F..%2F..%2Fpasswd":  # Encoded path for "../../passwd.txt"
                file_path = os.path.join("templates", "passwd.txt")
                try:
                    with open(file_path, "r") as f:
                        file_content = f.read()
                except FileNotFoundError:
                    error_message = "File not found or inaccessible. Check your input and try again!"
            else:
                error_message = "Invalid file path. Try again!"

        # If the user submits the admin name
        elif "submit_name" in request.form:
            admin_name = request.form.get('admin_name', '').strip()

            # Check if the admin name is correct
            if admin_name.lower() == "regan":
                session['progress'] = 3  # Update progress to unlock the next stage
                return redirect(url_for('command_injection'))
            else:
                error_message = "Admin name is incorrect. Try again!"

    return render_template(
        "file_inclusion.html",
        content=file_content,
        error=error_message
    )


@app.route('/command_injection', methods=['GET', 'POST'])
def command_injection():
    """
    Command Injection Challenge.
    """
    if session.get('progress', 0) < 3:
        return redirect(url_for('file_inclusion'))  # Prevent access if file inclusion isn't complete

    command_output = None
    error_message = None
    vault_key_input = None
    vault_key_correct = "CTF123KEY"  # Correct vault key

    # Simulated file system
    file_list = ["README.md", "vault_key.txt", "access.log"]
    file_contents = {
        "README.md": "Diagnostics tool active. Unauthorized access prohibited.",
        "vault_key.txt": "Vault Key: CTF123KEY",
        "access.log": "Access log: No anomalies detected.",
    }

    if request.method == 'POST':
        if "inject_command" in request.form:
            ip = request.form.get('ip', '').strip()

            # Simulate command execution
            if ";" in ip:
                injected_command = ip.split(";")[1].strip()  # Extract the injected command
                if "ls" in injected_command:
                    command_output = "\n".join(file_list)
                elif injected_command.startswith("cat "):
                    file_name = injected_command[4:].strip()  # Get the file name after "cat "
                    if file_name in file_contents:
                        command_output = file_contents[file_name]
                    else:
                        command_output = f"cat: {file_name}: No such file or directory"
                else:
                    command_output = f"Unknown command: {injected_command}"
            else:
                error_message = "Invalid IP address. Try injecting commands!"

        elif "submit_vault_key" in request.form:
            vault_key_input = request.form.get('vault_key', '').strip()

            if vault_key_input == vault_key_correct:
                session['progress'] = 4  # Update progress to unlock next stage
                return redirect(url_for('logic_flow'))
            else:
                error_message = "Incorrect vault key. Try again!"

    return render_template(
        "command_injection.html",
        output=command_output,
        error=error_message
    )


@app.route('/logic_flow', methods=['GET', 'POST'])
def logic_flow():
    """
    Logic Flow Exploit Challenge.
    """
    if session.get('progress', 0) < 4:
        return redirect(url_for('command_injection'))

    if request.method == 'POST':
        price = request.form.get('price', '500')
        if price == '0':
            session['progress'] = 5
            return redirect(url_for('hidden_form'))
        else:
            return render_template("logic_flow.html", error="Transaction failed. Try again!")

    return render_template("logic_flow.html")


@app.route('/hidden_form', methods=['GET', 'POST'])
def hidden_form():
    """
    Hidden Form Manipulation Challenge.
    """
    if session.get('progress', 0) < 5:
        return redirect(url_for('logic_flow'))

    if request.method == 'POST':
        price = request.form.get('price', '').strip()
        if price == '0':
            session['progress'] = 6
            return redirect(url_for('inspect_challenge'))
        else:
            return render_template("hidden_form.html", error="Invalid input. Try again!")

    return render_template("hidden_form.html")


@app.route('/inspect_challenge', methods=['GET', 'POST'])
def inspect_challenge():
    """
    Inspect Challenge (HackTheDoor).
    """
    if session.get('progress', 0) < 6:
        return redirect(url_for('hidden_form'))

    if request.method == 'POST':
        # Get user inputs from the form
        status = request.form.get('status', '').strip()
        door_status = request.form.get('door_status', '').strip()
        timeout = request.form.get('timeout', '').strip()

        # Check if all conditions are met
        if status == "ACCESS REFUTE" and door_status == "unlocked" and timeout == "0":
            session['progress'] = 7  # Update progress to unlock the next stage
            return redirect(url_for('steganography'))
        else:
            return render_template(
                "inspect_challenge.html",
                error="Submission failed! Ensure all values are correct: timeout=0, status=ACCESS REFUTE, door_status=unlocked."
            )

    return render_template("inspect_challenge.html")


@app.route('/steganography', methods=['GET', 'POST'])
def steganography():
    """
    Steganography Challenge.
    """
    if session.get('progress', 0) < 7:
        return redirect(url_for('inspect_challenge'))

    if request.method == 'POST':
        message = request.form.get('message', '').strip()
        if message == "CTF{play-with-me}":
            session['progress'] = 8
            return redirect(url_for('final_mission'))
        else:
            return render_template("steganography.html", error="Incorrect message. Try again!")

    return render_template("steganography.html")


@app.route('/final_mission', methods=['GET', 'POST'])
def final_mission():
    """
    Final Mission Challenge.
    """
    if session.get('progress', 0) < 8:
        return redirect(url_for('steganography'))

    if request.method == 'POST':
        # Get user inputs
        auth_token = request.form.get('auth_token', '').strip()
        account_number = request.form.get('account_number', '').strip()

        # Validate inputs
        if auth_token == "ACcess2923@#" and account_number == "123456789":
            session['progress'] = 9  # Update progress to mark completion
            return redirect(url_for('completion_form'))
        else:
            return render_template(
                "final_mission.html",
                error="Invalid Auth Token or Account Number. Try again!"
            )

    return render_template("final_mission.html")


@app.route('/completion_form', methods=['GET', 'POST'])
def completion_form():
    """
    Final Completion Form and Email Sending.
    """
    if session.get('progress', 0) < 9:
        return redirect(url_for('final_mission'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        twitter_handle = request.form.get('twitter', '').strip()

        if name and email:
            # Send congratulations email to user
            with open("response_email.txt", "r") as f:
                user_email_content = f.read()
            send_email(email, "Congratulations on Completing the Challenge!", user_email_content, html=True)

            # Send admin notification
            admin_emails = ["admin@cybergeneration.tech", "nerddyRegan@proton.me"]
            admin_message = f"""
            User completed challenge:
            Name: {name}
            Email: {email}
            Twitter: {twitter_handle}
            """
            for admin in admin_emails:
                send_email(admin, "Challenge Completed", admin_message)

            return render_template("completion.html", success="Congratulations! Emails have been sent.")
        else:
            return render_template("completion.html", error="Please fill in all fields.")

    return render_template("completion.html")


if __name__ == '__main__':
    app.run(debug=True)

