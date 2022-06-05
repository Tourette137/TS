from twilio.rest import Client
from sys import argv
from os import urandom
import random

# Getting a random 5-digit PIN
random.seed(urandom(25))
pin = '{:05d}'.format(random.randint(0,99999))

# Printing the pin
print(pin)

# Checking to see if phone number was provided
if len(argv) > 1:
    
    # Getting the phone number from the 1st command-line argument
    to_phone_no = argv[1]

    # Sending message to number with the Twilio API
    account_sid = 'AC4d79168f15dfb97d33a006601b2a9bde'
    auth_token = '1ccca417ee14f24c02b4ba6993d1501e'
    from_phone_no = '+19712575504'
    
    client = Client(account_sid, auth_token)

    message = client.messages.create(
            body="PIN : " + pin,
            from_= from_phone_no,
            to= to_phone_no)
