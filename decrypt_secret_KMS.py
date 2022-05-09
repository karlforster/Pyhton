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

kms_client = boto3.client("kms", region_name=AWS_REGION,
aws_access_key_id=ACCESS_KEY,
aws_secret_access_key=SECRET_KEY,
aws_session_token=SESSION_TOKEN
)

def decrypt(cipher_text, alias):
    """
    Decrypts ciphertext that was encrypted by a KMS key.
    """
    try:
        plain_text = kms_client.decrypt(KeyId=alias,
                                        CiphertextBlob=bytes(
                                            base64.b64decode(cipher_text)))
    except ClientError:
        logger.exception('Could not decrypt the string.')
        raise
    else:
        return plain_text['Plaintext']


if __name__ == '__main__':
    # Constants
    CIPHER_BLOB = '647634346784368273647647664' #encrypted string already encrypted with the KMS key
    KEY_ALIAS = 'arn:aws:kms:<region>:<account>:alias/<name>'
    logger.info('Decrypting...')
    kms = decrypt(CIPHER_BLOB, KEY_ALIAS)
    print(kms.decode('utf8'))
    logger.info(f"Decrypted string: {kms.decode('utf8')}.")