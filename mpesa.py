import base64
import datetime

import requests
from requests.auth import HTTPBasicAuth

def generate_token(consumer_key, consumer_secret):
    api_url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
    response = requests.get(api_url, auth=HTTPBasicAuth(consumer_key, consumer_secret))
    print(response.text)
    json_response = response.json()
    return json_response["access_token"]


def lipa_na_mpesa_online(phone_number, amount):
    consumer_key = "YENBbIEi5GHaHsy9CzlkQrBESqoYpCXsHK2WrpzBjtGSKg31"
    consumer_secret = "64fYZAtqZ72Xt6KVYnaUXrp2HXb0iAVJZ7sibVTCUo8Qx7VE7mBFy6UVuD0zywDO"
    access_token = generate_token(consumer_key, consumer_secret)
    # access_token = "pAqSYZ72RSpRGb7G4CX4DwTFp5B7"
    api_url = "https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
    business_short_code = "4183161"
    passkey = "cfe77f0c6d37654d134f449d957612e82b6c93c77e1fe592a9ad0651aca2842b"
    callback_url = "https://bgcapps.pythonanywhere.com/mpesa/callback"
    timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    data_to_encode = business_short_code + passkey + timestamp
    password = base64.b64encode(data_to_encode.encode()).decode('utf-8')
    payload = {
        "BusinessShortCode": business_short_code,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": amount,
        "PartyA": phone_number,
        "PartyB": business_short_code,
        "PhoneNumber": phone_number,
        "CallBackURL": callback_url,
        "AccountReference": "TestPayment",
        "TransactionDesc": "Payment for services"
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    response = requests.post(api_url, json=payload, headers=headers)
    return response.json()

print(lipa_na_mpesa_online('254115306792',8))