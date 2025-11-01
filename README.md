# SecureBank System

**SecureBank System** is a Flask-based secure online banking web application built with advanced authentication, encryption, and auditing mechanisms. It demonstrates strong cybersecurity principles including secure password hashing, data encryption, session management, and SQL injection/XSS protection.

---

## Features

### Security
- Password hashing with **Werkzeug** (`generate_password_hash`, `check_password_hash`)
- Encryption of sensitive user data using **Fernet (AES-128)** from `cryptography`
- Input sanitization and validation to prevent **XSS and SQL injection**
- Automatic **account lockout** after 5 failed login attempts
- **Session timeout** after 5 minutes of inactivity
- **Audit logging** for all user actions
- Secure **file upload** with size and type restrictions (PDF, PNG, JPG, JPEG)

### Core Modules
- **User Registration & Login**
- **Dashboard** with balance and recent transaction summary
- **Transaction System** (Deposit, Withdraw, Transfer)
- **Profile Management** (editable personal info, encrypted SSN)
- **Audit Log Viewer**
- **Secure File Uploads**
- Modern **Dark UI Templates** with responsive design

---

## Tech Stack

| Layer | Technology |
|-------|-------------|
| Backend | Flask (Python) |
| Database | SQLite |
| Security | `cryptography`, `werkzeug.security`, `secrets`, `hashlib` |
| Frontend | HTML5, CSS3, JS (Custom dark theme templates) |
| Logging | Python `logging` module |
| Optional | `qrcode` for QR-based account actions |

---

## Installation & Setup

### 1️⃣ Clone the repository
```bash
git clone https://github.com/yourusername/SecureBank.git
cd SecureBank
```

### 2️⃣ Create a virtual environment
```bash
python -m venv venv
venv\Scripts\activate   # On Windows
source venv/bin/activate  # On macOS/Linux
```

### 3️⃣ Install dependencies
```bash
pip install flask cryptography werkzeug qrcode pillow
```

*(If QR code features are optional, you can skip installing `qrcode`)*

### 4️⃣ Initialize the database
Run the Flask app once to create the database tables automatically:
```bash
python SecureBankingSystem.py
```

### 5️⃣ Start the server
```bash
flask run
```
Or:
```bash
python SecureBankingSystem.py
```

Then visit **http://127.0.0.1:5000** in your browser.

---

## Security Highlights

- **AES-128 encryption** for sensitive information such as SSN.
- **Password strength enforcement** (min length, uppercase, digits, special chars).
- **Activity tracking** with IP and timestamp logs.
- **Session-based authentication** with idle timeout.
- **Secure uploads** protected from path traversal or malicious extensions.

---



## Author

**Developed by:** Sehar Nadeem 
**Institution:** FAST University Islamabad  
**Semester:** 7th 
