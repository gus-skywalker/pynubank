import os
import uuid
from datetime import timedelta
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from cryptography.fernet import Fernet
from flask import Flask, jsonify, request
from pynubank import Nubank

app = Flask(__name__)

class CachedNubank:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(CachedNubank, cls).__new__(cls)
        return cls._instance

    def __init__(self, nu):
        if not hasattr(self, 'initialized'):  # Prevent re-initialization
            self.nu = nu
            self.bills = None
            self.bill_details_cache = {}
            self.card_statements = None
            self.credit_card_balance = None
            self.initialized = True

    def authenticate_if_needed(self, access_token_nubank, cert_path):
        try:
            self.nu.authenticate_with_refresh_token(access_token_nubank, cert_path=cert_path)
        except:
            self.nu.authenticate()

    def get_bills(self, access_token_nubank, cert_path):
        if not self.bills:
            self.authenticate_if_needed(access_token_nubank, cert_path)
            self.bills = self.nu.get_bills()
        return self.bills

    def get_bill_details(self, bill, access_token_nubank, cert_path):
        bill_link = bill['_links']['self']['href']
        if bill_link not in self.bill_details_cache:
            self.authenticate_if_needed(access_token_nubank, cert_path)
            self.bill_details_cache[bill_link] = self.nu.get_bill_details(bill)
        return self.bill_details_cache[bill_link]

    def get_card_statements(self, access_token_nubank, cert_path):
        if not self.card_statements:
            self.authenticate_if_needed(access_token_nubank, cert_path)
            self.card_statements = self.nu.get_card_statements()
        return self.card_statements

    def get_credit_card_balance(self, access_token_nubank, cert_path):
        if not self.credit_card_balance:
            self.authenticate_if_needed(access_token_nubank, cert_path)
            self.credit_card_balance = self.nu.get_credit_card_balance()
        return self.credit_card_balance

# Set the secret key and JWT configuration
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Change this in production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

jwt = JWTManager(app)
# Initialize Nubank API client and authenticate
nubank = Nubank()
# With certificate generated
# nubank.authenticate_with_cert(CPF, PASSWORD, cert_path='/Users/gugadam/workspaces/openbank/pynubank/cert.p12')
cached_nubank = CachedNubank(nubank)

# Encryption key (store it securely, not hard-coded in production)
ENCRYPTION_KEY = b'27YlIttHFd0XDuCogJYZH64TtdxWV1O4FPuNVXMcfJY='
cipher = Fernet(ENCRYPTION_KEY)

def get_cert_path(cpf):
    # Buscar caminho criptografado do certificado do armazenamento seguro
    encrypted_cert_path = secure_storage_get_cert_path(cpf)
    cert_path = cipher.decrypt(encrypted_cert_path.encode()).decode()
    return cert_path

def secure_storage_get_cert_path(cpf):
    # Implementação para buscar do armazenamento seguro (exemplo, banco de dados)
    # Este exemplo retorna um caminho codificado
    return 'encrypted_cert_path_base64'

@app.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.json
    cpf = data.get('cpf')
    password = data.get('password')

    if not cpf or not password:
        return jsonify({'error': 'CPF and password are required'}), 400

    try:
        cert_path = get_cert_path(cpf)  # Fetch the certificate path securely
        refresh_token_nubank = nubank.authenticate_with_cert(cpf, password, cert_path=cert_path)
        access_token = create_access_token(identity=cpf, additional_claims={'refresh_token_nubank': refresh_token_nubank})
        print(refresh_token_nubank)
        return jsonify({'access_token': access_token}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/nubank-data/get-bills', methods=['GET'])
@jwt_required()
def get_nubank_data():
    cpf = get_jwt_identity()
    claims = get_jwt()
    access_token_nubank = claims.get('refresh_token_nubank')

    try:
        cert_path = get_cert_path(cpf)
        faturas = cached_nubank.get_bills(access_token_nubank, cert_path)
        return jsonify(faturas)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/nubank-data/bill-details', methods=['POST'])
@jwt_required()
def get_nubank_bill_details():
    cpf = get_jwt_identity()
    data = request.json

    if 'bill' not in data or '_links' not in data['bill'] or 'self' not in data['bill']['_links']:
        return jsonify({'error': 'Invalid request. Missing bill "self" link.'}), 400

    bill = data['bill']
    claims = get_jwt()
    access_token_nubank = claims.get('refresh_token_nubank')

    try:
        cert_path = get_cert_path(cpf)
        bill_details = cached_nubank.get_bill_details(bill, access_token_nubank, cert_path)
        return jsonify(bill_details)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/nubank-data/card-statements', methods=['GET'])
@jwt_required()
def get_nubank_card_statements():
    cpf = get_jwt_identity()
    claims = get_jwt()
    access_token_nubank = claims.get('refresh_token_nubank')

    try:
        cert_path = get_cert_path(cpf)
        card_statements = cached_nubank.get_card_statements(access_token_nubank, cert_path)
        return jsonify({'card_statements': card_statements})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/nubank-data/credit-card-balance', methods=['GET'])
@jwt_required()
def get_credit_card_balance():
    cpf = get_jwt_identity()
    claims = get_jwt()
    access_token_nubank = claims.get('refresh_token_nubank')

    try:
        cert_path = get_cert_path(cpf)
        credit_card_balance = cached_nubank.get_credit_card_balance(access_token_nubank, cert_path)
        return jsonify({'credit_card_balance': credit_card_balance})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Directory to store the certificates
CERT_DIR = 'resource/certificates'  # Alterar para o caminho do diretório desejado

if not os.path.exists(CERT_DIR):
    os.makedirs(CERT_DIR)

@app.route('/generate-cert', methods=['POST'])
def generate_cert():
    data = request.json
    cpf = data.get('cpf')
    password = data.get('password')

    if not cpf or not password:
        return jsonify({'error': 'CPF and password are required'}), 400

    try:
        # Generate a unique filename for the certificate
        cpf_part = cpf[-4:]  # Use last 4 digits of CPF
        cert_filename = f"{uuid.uuid4()}_{cpf_part}.p12"
        cert_path = os.path.join(CERT_DIR, cert_filename)

        # Authenticate and generate the certificate
        nubank.authenticate_with_cert(cpf, password, cert_path)

        return jsonify({'message': 'Certificate generated successfully', 'cert_id': cert_filename}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(port=5000)