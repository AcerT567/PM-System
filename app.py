import os
from flask import Flask, render_template, redirect, url_for, flash, request, abort, Response
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import create_engine, or_
from sqlalchemy.orm import sessionmaker, scoped_session
from models import Base, User, Patient, Note
from forms import LoginForm, PatientForm, NoteForm, RegistrationForm
from functools import wraps
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import csv
import io
from flask_talisman import Talisman

app = Flask(__name__)
# Use environment SECRET_KEY if provided
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'replace-this-with-a-secure-random-value-in-production')

# Security headers / HTTPS
Talisman(app, content_security_policy=None)

DB_PATH = os.path.join(os.path.dirname(__file__), 'pms.db')
engine = create_engine(f'sqlite:///{DB_PATH}', echo=False, future=True)
Base.metadata.create_all(engine)
SessionFactory = sessionmaker(bind=engine, future=True)
db = scoped_session(SessionFactory)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Serializer for email tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- helpers ---
def role_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role not in allowed_roles and current_user.role != 'admin':
                flash('Access denied: insufficient privileges.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@login_manager.user_loader
def load_user(user_id):
    return db().query(User).get(int(user_id))

def send_verification_email(recipient_email, token):
    # Try to send via SMTP if environment variables set; otherwise print to console
    mail_server = os.environ.get('MAIL_SERVER')
    if mail_server:
        import smtplib
        from email.message import EmailMessage
        port = int(os.environ.get('MAIL_PORT', 25))
        username = os.environ.get('MAIL_USERNAME')
        password = os.environ.get('MAIL_PASSWORD')
        use_tls = os.environ.get('MAIL_USE_TLS', 'False').lower() == 'true'
        msg = EmailMessage()
        msg['Subject'] = 'Verify your account'
        msg['From'] = username or 'no-reply@example.com'
        msg['To'] = recipient_email
        link = url_for('confirm_email', token=token, _external=True)
        msg.set_content(f'Please verify your account by visiting: {link}')
        s = smtplib.SMTP(mail_server, port, timeout=10)
        try:
            if use_tls:
                s.starttls()
            if username and password:
                s.login(username, password)
            s.send_message(msg)
        finally:
            s.quit()
        print('Sent verification email to', recipient_email)
    else:
        # Fallback for development: print link to console
        link = url_for('confirm_email', token=token, _external=True)
        print('\n=== Email verification link (console fallback) ===')
        print(f'To: {recipient_email}')
        print(link)
        print('===============================================\n')

# --- routes ---
@app.route('/')
@login_required
def index():
    session = db()
    # Pagination and search/filter params
    q = request.args.get('q', '').strip()
    gender = request.args.get('gender', '').strip()
    page = max(int(request.args.get('page', 1)), 1)
    per_page = 8

    query = session.query(Patient)
    if q:
        like_q = f'%{q}%'
        query = query.filter(or_(
            Patient.first_name.ilike(like_q),
            Patient.last_name.ilike(like_q),
            Patient.phone.ilike(like_q),
            Patient.email.ilike(like_q)
        ))
    if gender:
        query = query.filter(Patient.gender == gender)

    total = query.count()
    patients = query.order_by(Patient.created_at.desc()).offset((page-1)*per_page).limit(per_page).all()
    total_pages = (total + per_page - 1) // per_page

    return render_template('index.html', patients=patients, page=page, total_pages=total_pages, q=q, gender=gender)

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        session = db()
        user = session.query(User).filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET','POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        session = db()
        existing = session.query(User).filter_by(username=form.username.data).first()
        if existing:
            flash('Username already exists.', 'warning')
            return redirect(url_for('register'))
        # Create user with inactive flag via role 'pending' to require email confirmation
        hashed = generate_password_hash(form.password.data)
        u = User(username=form.username.data, password_hash=hashed, role=form.role.data)
        session.add(u)
        session.commit()
        token = serializer.dumps(u.username, salt='email-confirm')
        send_verification_email(form.email.data, token)
        flash('Registration successful. A verification link was sent to your email (or printed to console).', 'info')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        username = serializer.loads(token, salt='email-confirm', max_age=60*60*24)  # 24 hours
    except SignatureExpired:
        flash('The verification link has expired.', 'danger')
        return redirect(url_for('login'))
    except BadSignature:
        flash('Invalid verification token.', 'danger')
        return redirect(url_for('login'))
    session = db()
    user = session.query(User).filter_by(username=username).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))
    # For this demo, confirmation doesn't change role; in production you might set a 'confirmed' flag.
    flash('Email verified. You can now login.', 'success')
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/patients/new', methods=['GET','POST'])
@login_required
@role_required('doctor', 'nurse')
def new_patient():
    form = PatientForm()
    if form.validate_on_submit():
        session = db()
        p = Patient(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            dob=form.dob.data,
            gender=form.gender.data,
            phone=form.phone.data,
            email=form.email.data,
            address=form.address.data
        )
        session.add(p)
        session.commit()
        flash('Patient created.', 'success')
        return redirect(url_for('index'))
    return render_template('patient_form.html', form=form, action='New Patient')

@app.route('/patients/<int:pid>')
@login_required
@role_required('doctor', 'nurse')
def view_patient(pid):
    session = db()
    p = session.query(Patient).get(pid)
    if not p:
        abort(404)
    notes = p.notes
    return render_template('patient_view.html', patient=p, notes=notes)

@app.route('/patients/<int:pid>/edit', methods=['GET','POST'])
@login_required
@role_required('doctor', 'nurse')
def edit_patient(pid):
    session = db()
    p = session.query(Patient).get(pid)
    if not p:
        abort(404)
    form = PatientForm(obj=p)
    if form.validate_on_submit():
        p.first_name = form.first_name.data
        p.last_name = form.last_name.data
        p.dob = form.dob.data
        p.gender = form.gender.data
        p.phone = form.phone.data
        p.email = form.email.data
        p.address = form.address.data
        session.commit()
        flash('Patient updated.', 'success')
        return redirect(url_for('view_patient', pid=pid))
    return render_template('patient_form.html', form=form, action='Edit Patient')

@app.route('/patients/<int:pid>/delete', methods=['POST'])
@login_required
@role_required('doctor', 'nurse')
def delete_patient(pid):
    session = db()
    p = session.query(Patient).get(pid)
    if not p:
        abort(404)
    session.delete(p)
    session.commit()
    flash('Patient deleted.', 'info')
    return redirect(url_for('index'))

@app.route('/patients/<int:pid>/notes/new', methods=['GET','POST'])
@login_required
@role_required('doctor')  # only doctors can add notes
def new_note(pid):
    session = db()
    p = session.query(Patient).get(pid)
    if not p:
        abort(404)
    form = NoteForm()
    if form.validate_on_submit():
        note = Note(patient_id=p.id, author_id=current_user.id, title=form.title.data, body=form.body.data)
        session.add(note)
        session.commit()
        flash('Note added.', 'success')
        return redirect(url_for('view_patient', pid=pid))
    return render_template('note_form.html', form=form, patient=p, action='Add Note')

@app.route('/notes/<int:nid>/delete', methods=['POST'])
@login_required
@role_required('doctor')
def delete_note(nid):
    session = db()
    note = session.query(Note).get(nid)
    if not note:
        abort(404)
    session.delete(note)
    session.commit()
    flash('Note deleted.', 'info')
    return redirect(url_for('view_patient', pid=note.patient_id))

# CSV export for patients
@app.route('/export/patients')
@login_required
@role_required('doctor', 'nurse')
def export_patients():
    session = db()
    patients = session.query(Patient).all()
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(['id','first_name','last_name','dob','gender','phone','email','address','created_at'])
    for p in patients:
        writer.writerow([p.id,p.first_name,p.last_name,p.dob,p.gender,p.phone,p.email,p.address,p.created_at])
    output = si.getvalue()
    return Response(output, mimetype='text/csv', headers={'Content-Disposition':'attachment;filename=patients.csv'})

# CSV export for notes
@app.route('/export/notes')
@login_required
@role_required('doctor', 'nurse')
def export_notes():
    session = db()
    notes = session.query(Note).all()
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(['id','patient_id','author_id','title','body','created_at'])
    for n in notes:
        writer.writerow([n.id,n.patient_id,n.author_id,n.title,n.body,n.created_at])
    output = si.getvalue()
    return Response(output, mimetype='text/csv', headers={'Content-Disposition':'attachment;filename=notes.csv'})

# CSV import for patients
@app.route('/import/patients', methods=['GET','POST'])
@login_required
@role_required('doctor', 'nurse')
def import_patients():
    if request.method == 'POST':
        f = request.files.get('file')
        if not f:
            flash('No file uploaded.', 'warning')
            return redirect(url_for('import_patients'))
        stream = io.StringIO(f.stream.read().decode('utf-8'))
        reader = csv.DictReader(stream)
        session = db()
        count = 0
        for row in reader:
            p = Patient(
                first_name=row.get('first_name') or row.get('First Name') or '',
                last_name=row.get('last_name') or row.get('Last Name') or '',
                dob=row.get('dob') or '',
                gender=row.get('gender') or '',
                phone=row.get('phone') or '',
                email=row.get('email') or '',
                address=row.get('address') or ''
            )
            session.add(p)
            count += 1
        session.commit()
        flash(f'Imported {count} patients.', 'success')
        return redirect(url_for('index'))
    return render_template('import_patients.html')

# CSV import for notes - expects patient id and author username
@app.route('/import/notes', methods=['GET','POST'])
@login_required
@role_required('doctor')
def import_notes():
    if request.method == 'POST':
        f = request.files.get('file')
        if not f:
            flash('No file uploaded.', 'warning')
            return redirect(url_for('import_notes'))
        stream = io.StringIO(f.stream.read().decode('utf-8'))
        reader = csv.DictReader(stream)
        session = db()
        count = 0
        for row in reader:
            patient_id = row.get('patient_id') or row.get('Patient ID')
            author_username = row.get('author_username') or row.get('author') or ''
            author = session.query(User).filter_by(username=author_username).first()
            if not (patient_id and author):
                continue
            n = Note(patient_id=int(patient_id), author_id=author.id, title=row.get('title') or '', body=row.get('body') or '')
            session.add(n)
            count += 1
        session.commit()
        flash(f'Imported {count} notes.', 'success')
        return redirect(url_for('index'))
    return render_template('import_notes.html')

# User listing and management - admin only (keep simple)
@app.route('/users')
@login_required
def list_users():
    if current_user.role != 'admin':
        flash('Access denied: admin only.', 'danger')
        return redirect(url_for('index'))
    session = db()
    users = session.query(User).all()
    return render_template('users.html', users=users)

@app.route('/users/create', methods=['GET','POST'])
@login_required
def create_user():
    if current_user.role != 'admin':
        flash('Access denied: admin only.', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        if not username or not password or not role:
            flash('Provide username, password, role.', 'warning')
            return redirect(url_for('create_user'))
        session = db()
        existing = session.query(User).filter_by(username=username).first()
        if existing:
            flash('User exists.', 'warning')
            return redirect(url_for('create_user'))
        u = User(username=username, password_hash=generate_password_hash(password), role=role)
        session.add(u)
        session.commit()
        flash('User created.', 'success')
        return redirect(url_for('list_users'))
    return render_template('create_user.html')

if __name__ == '__main__':
    # For demo only: ensure DB exists
    if not os.path.exists(DB_PATH):
        print('Database not found. Run init_db.py first to create sample users.')
    # In production, set debug=False and run behind a real WSGI server (gunicorn) and HTTPS
    app.run(debug=True)
