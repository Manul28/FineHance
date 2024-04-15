from flask import Flask, render_template, request, flash, redirect, url_for, session, jsonify, Response, send_file
from flask_sqlalchemy import SQLAlchemy
from wtforms import Form, StringField, PasswordField, IntegerField, validators
from wtforms.validators import DataRequired, Email, Length, EqualTo
from passlib.hash import sha256_crypt
from functools import wraps
import timeago
import datetime
from itsdangerous.url_safe import URLSafeTimedSerializer as Serializer
from flask_mail import Mail, Message
import plotly.graph_objects as go
import pandas as pd

app = Flask(__name__, static_url_path='/static')
app.config.from_pyfile('config.py')
app.secret_key = 'abcd2123445'

# Configure SQLite with SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tracker.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
mail = Mail(app)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Define Transaction model
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('transactions', lazy=True))
    amount = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)

# Define forms
class SignUpForm(Form):
    first_name = StringField('First Name', [validators.Length(min=1, max=100)])
    last_name = StringField('Last Name', [validators.Length(min=1, max=100)])
    email = StringField('Email address', [validators.DataRequired(), validators.Email()])
    username = StringField('Username', [validators.Length(min=4, max=100)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

class LoginForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=100)])
    password = PasswordField('Password', [validators.DataRequired()])

class TransactionForm(Form):
    amount = IntegerField('Amount', validators=[DataRequired()])
    description = StringField('Description', [validators.Length(min=1)])
    category = StringField('Category', [validators.Length(min=1)])

class RequestResetForm(Form):
    email = StringField('Email address', [validators.DataRequired(), validators.Email()])

class ResetPasswordForm(Form):
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')



# Helper function for login_required decorator
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Please login', 'info')
            return redirect(url_for('login'))
    return wrap

# Index route
@app.route('/')
def index():
    return render_template('index.html')

# About route
@app.route('/about')
def about():
    return render_template('about.html')

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm(request.form)
    if request.method == 'POST' and form.validate():
        first_name = form.first_name.data
        last_name = form.last_name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Check if email or username already exists
        if User.query.filter_by(email=email).first():
            flash('The entered email address has already been taken. Please try using or creating another one.', 'info')
            return redirect(url_for('signup'))
        if User.query.filter_by(username=username).first():
            flash('The entered username has already been taken. Please try using or creating another one.', 'info')
            return redirect(url_for('signup'))

        # Create new user
        new_user = User(first_name=first_name, last_name=last_name, email=email, username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        flash('You are now registered and can log in', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password_input = form.password.data

        user = User.query.filter_by(username=username).first()

        if user:
            if sha256_crypt.verify(password_input, user.password):
                session['logged_in'] = True
                session['username'] = username
                session['user_id'] = user.id
                flash('You are now logged in', 'success')
                return redirect(url_for('addTransactions'))
            else:
                error = 'Invalid Password'
                return render_template('login.html', form=form, error=error)
        else:
            error = 'Username not found'
            return render_template('login.html', form=form, error=error)

    return render_template('login.html', form=form)

# Logout route
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# Add Transactions route
@app.route('/addTransactions', methods=['GET', 'POST'])
@is_logged_in
def addTransactions():
    if request.method == 'POST':
        amount = request.form['amount']
        description = request.form['description']
        category = request.form['category']

        new_transaction = Transaction(user_id=session['user_id'], amount=amount, description=description, category=category)
        db.session.add(new_transaction)
        db.session.commit()

        flash('Transaction Successfully Recorded', 'success')
        return redirect(url_for('addTransactions'))
    else:
        transactions = Transaction.query.filter_by(user_id=session['user_id']).order_by(Transaction.date.desc()).all()
        totalExpenses = sum(transaction.amount for transaction in transactions)
        return render_template('addTransactions.html', totalExpenses=totalExpenses, transactions=transactions)

# Edit Transaction route
@app.route('/editTransaction/<int:id>', methods=['GET', 'POST'])
@is_logged_in
def editTransaction(id):
    transaction = Transaction.query.get(id)
    form = TransactionForm(request.form, obj=transaction)
    if request.method == 'POST' and form.validate():
        form.populate_obj(transaction)
        db.session.commit()
        flash('Transaction Updated', 'success')
        return redirect(url_for('transactionHistory'))
    return render_template('editTransaction.html', form=form)

# Delete Transaction route
@app.route('/deleteTransaction/<int:id>', methods=['POST'])
@is_logged_in
def deleteTransaction(id):
    transaction = Transaction.query.get(id)
    db.session.delete(transaction)
    db.session.commit()
    flash('Transaction Deleted', 'success')
    return redirect(url_for('transactionHistory'))

# Reset Password Request route
@app.route("/reset_request", methods=['GET', 'POST'])
def reset_request():
    form = RequestResetForm(request.form)
    if request.method == 'POST' and form.validate():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            s = Serializer(app.config['SECRET_KEY'], 1800)
            token = s.dumps({'user_id': user.id}).decode('utf-8')
            msg = Message('Password Reset Request',
                          sender='noreply@demo.com', recipients=[email])
            msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make password reset request then simply ignore this email and no changes will be made.
Note: This link is valid only for 30 mins from the time you requested a password change request.
'''
            mail.send(msg)
            flash(
                'An email has been sent with instructions to reset your password.', 'info')
            return redirect(url_for('login'))
        else:
            flash(
                'There is no account with that email. You must register first.', 'warning')
            return redirect(url_for('signup'))
    return render_template('reset_request.html', form=form)

# Reset Password route
@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    s = Serializer(app.config['SECRET_KEY'])
    try:
        user_id = s.loads(token)['user_id']
    except:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    user = User.query.get(user_id)
    form = ResetPasswordForm(request.form)
    if request.method == 'POST' and form.validate():
        user.password = sha256_crypt.encrypt(str(form.password.data))
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)

# Category Wise Pie Chart For Current Year As Percentage route
@app.route('/category')
@is_logged_in
def createBarCharts():
    transactions = db.session.query(db.func.sum(Transaction.amount).label('amount'), Transaction.category).filter(db.func.strftime("%Y", Transaction.date) == str(datetime.datetime.now().year)).filter_by(user_id=session['user_id']).group_by(Transaction.category).all()

    labels = [transaction.category for transaction in transactions]
    values = [transaction.amount for transaction in transactions]

    fig = go.Figure(data=[go.Pie(labels=labels, values=values)])
    fig.update_traces(textinfo='label+value', hoverinfo='percent')
    fig.update_layout(
        title_text='Category Wise Pie Chart For Current Year')
    fig.show()
    return redirect(url_for('addTransactions'))

# Daily Line Chart route
@app.route('/daily_line')
@is_logged_in
def dailyLineChart():
    transactions = db.session.query(db.func.date(Transaction.date).label('transaction_date'),
                                    db.func.sum(Transaction.amount).label('total_amount')).filter(db.func.strftime("%Y-%m", Transaction.date) == str(datetime.datetime.now().year)+'-'+str(datetime.datetime.now().month)).filter_by(user_id=session['user_id']).group_by(db.func.date(Transaction.date)).all()

    dates = [transaction.transaction_date for transaction in transactions]
    amounts = [transaction.total_amount for transaction in transactions]

    fig = go.Figure(data=go.Scatter(x=dates, y=amounts, mode='lines+markers'))
    fig.update_layout(title_text='Daily Expenses Line Chart', xaxis_title='Date', yaxis_title='Total Amount')
    fig.show()
    return redirect(url_for('addTransactions'))

# Excel Form route
@app.route('/excel_form')
@is_logged_in
def excelForm():
    transactions = Transaction.query.filter_by(user_id=session['user_id']).all()
    df = pd.DataFrame([(t.id, t.user_id, t.amount, t.description, t.category, t.date) for t in transactions],
                      columns=['ID', 'User ID', 'Amount', 'Description', 'Category', 'Date'])

    # Save DataFrame to Excel file
    excel_file_path = 'transactions_data.xlsx'
    df.to_excel(excel_file_path, index=False)

    # Start the download
    return send_file(excel_file_path, as_attachment=True, download_name='transactions_data.xlsx')


@app.route('/deleteCurrentMonthTransactions/<int:id>', methods=['POST'])
@is_logged_in
def deleteCurrentMonthTransaction(id):
    transaction = Transaction.query.get(id)
    if transaction:
        db.session.delete(transaction)
        db.session.commit()
        flash('Transaction Deleted', 'success')
    else:
        flash('Transaction not found', 'danger')
    return redirect(url_for('addTransactions'))


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)