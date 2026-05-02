import json
import boto3
import os
import zipfile

def download_dir(client, resource, dist, local='/tmp', bucket=os.environ["RECEIPTS_BUCKET"]):
    paginator = client.get_paginator('list_objects')
    for result in paginator.paginate(Bucket=bucket, Delimiter='/', Prefix=dist):
        if result.get('CommonPrefixes') is not None:
            for subdir in result.get('CommonPrefixes'):
                download_dir(client, resource, subdir.get('Prefix'), local, bucket)
        if result.get('Contents') is not None:
            for file in result.get('Contents'):
                if not os.path.exists(os.path.dirname(local + os.sep + file.get('Key'))):
                    os.makedirs(os.path.dirname(local + os.sep + file.get('Key')))
                resource.meta.client.download_file(bucket, file.get('Key'), local + os.sep + file.get('Key'))


def lambda_handler(event, context):
    # FIX: Verify admin identity before proceeding
    requesting_user_id = event.get("userId", "")
    if not requesting_user_id:
        return {
            "statusCode": 403,
            "body": json.dumps({"status": "err", "msg": "Forbidden"})
        }

    import boto3 as b3
    ddb = b3.resource('dynamodb')
    import os as _os
    user_table = ddb.Table(_os.environ.get("usertable", ""))
    resp = user_table.get_item(Key={"userId": requesting_user_id})
    if not resp.get("Item", {}).get("isAdmin", False):
        return {
            "statusCode": 403,
            "body": json.dumps({"status": "err", "msg": "Forbidden: admins only"})
        }

    # Original code — only reached by verified admins
    client = boto3.client('s3')
    resource = boto3.resource('s3')
    m = ""
    d = ""
    y = event["year"]
    if "month" in event:
        m = event["month"] + "/"
        if "day" in event:
            d = event["day"] + "/"

    prefix = "{}/{}/{}".format(y, m, d)
    bucket = os.environ["RECEIPTS_BUCKET"]
    download_dir(client, resource, prefix, '/tmp', bucket)
    zip_file = "{}dvsa-order-receipts.zip".format(prefix.replace("/", "-"))

    zf = zipfile.ZipFile("/tmp/" + zip_file, "w")
    for dirname, subdirs, files in os.walk("/tmp"):
        zf.write(dirname)
        for filename in files:
            if filename.endswith(".txt"):
                zf.write(os.path.join(dirname, filename))
    zf.close()

    client.upload_file("/tmp/" + zip_file, bucket, "zip/" + zip_file)
    signed_link = client.generate_presigned_url('get_object',
                                                Params={'Bucket': bucket, 'Key': "zip/" + zip_file},
                                                ExpiresIn=3600)

    res = {"status": "ok", "download_url": signed_link}
    return res
