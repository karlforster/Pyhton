import base64
import json
import logging

import boto3
from botocore.exceptions import ClientError

AWS_REGION = 'eu-central-1'

# logger config
logger = logging.getLogger()
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s: %(levelname)s: %(message)s')

#below requires AWS SSO environemnt variables set https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html
kms_client = boto3.client("kms", region_name=AWS_REGION,
aws_access_key_id=ACCESS_KEY,
aws_secret_access_key=SECRET_KEY,
aws_session_token=SESSION_TOKEN
)


def encrypt(secret, alias):
    """
    Encrypts plaintext into ciphertext by using a KMS key.
    """
    try:
        cipher_text = kms_client.encrypt(
            KeyId=alias,
            Plaintext=bytes(secret, encoding='utf8'),
        )
    except ClientError:
        logger.exception('Could not encrypt the string.')
        raise
    else:
        return base64.b64encode(cipher_text["CiphertextBlob"])


if __name__ == '__main__':
    # Constants
    SECRET = 'random string'
    KEY_ALIAS = 'arn:aws:kms:<region>:<account>:alias/<name>'
    logger.info('Encrypting...')
    kms = encrypt(SECRET, KEY_ALIAS)
    logger.info(f'Encrypted string: {kms}.')