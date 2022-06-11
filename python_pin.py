from twilio.rest import Client
from sys import argv
from os import urandom
import random

# Generate random PIN with 5 digits
random.seed(urandom(25))
pin = '{:05d}'.format(random.randint(0,99999))

# Print the pin to stdout (which should be father's pipe)
print(pin)

if len(argv) > 1:

    # Twilio API infos
    account_sid = 'AC4d79168f15dfb97d33a006601b2a9bde'
    auth_token = '1ccca417ee14f24c02b4ba6993d1501e'

    twilio_phone_number = '+19712575504'
    dest_phone_number = argv[1]
    
    client = Client(account_sid, auth_token)

    message = client.messages.create(
                body  = "PIN : " + pin,
                from_ = twilio_phone_number,
                to    = dest_phone_number)
