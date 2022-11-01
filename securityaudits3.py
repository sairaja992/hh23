#!/usr/bin/env python3
""" 
Description - This Scritp will get the Today-s3_Findings data from Scout2-History 
bucket for each account and write Findings data to dynamodb table

Update Table    -   security-audit-S3

Requrements - python3, Scout2 Report, imported libraries, aws crossaccount role,dynamodb,sns subscription,s3 bucket access

Output - Writing findings data for each rule in to dynamodbTable for each AWS account. 

import re
import os
import datetime
import dateutil
import boto3, json, time, datetime, sys
from dateutil.parser import parse
import traceback
from dateutil import tz, parser
from datetime import timedelta, date, datetime, timezone
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
sts = boto3.client('sts')
ClientSSM = boto3.client('ssm', 'us-east-2')
sns_client = boto3.client('sns')
dynamodb_resource = boto3.resource('dynamodb','us-east-2')
dynamodb_client = boto3.client('dynamodb','us-east-2')  # conection to the dynamo db
update_table_primarykey='Accountid'
update_table_sort_key='Rulename'
service='s3'
BUCKET_NAME = 'ue2'  # replace with your bucket name  
s3 = boto3.resource('s3')
Today_date=datetime.now()
s3_update_date=today_date.strftime("%m-%d-%Y")
accounts_list_table=dynamodb_resource.Table('awsaccounts-crossaccountrole-list')
def lambda_handler(event, context):
    running_date=today_date.strftime('%Y-%m-%dT%H:%M:%SZ')
    alrt=''
    try:
        #############################################################   
            #SCANNING THE LASTEVALUATEDKEY FROM PARAMATER STORE
        #############################################################
        try:
            get_evaluated_key=ClientSSM.get_parameter(Name='Scout2-S3-Startkey')
        except :
            response = ClientSSM.put_parameter(Name='Scout2-S3-Startkey',Description='s3LastEvaluatedKey',Value='Null',
            Type='String',Overwrite=True)
            #print("Value Updated--Version as",response  )
            get_evaluated_key=ClientSSM.get_parameter(Name='Scout2-S3-Startkey')
        if get_evaluated_key['Parameter']['Value']=="Null":
            accounts_list_table_scan = accounts_list_table.scan(Select='ALL_ATTRIBUTES',Limit=5,ConsistentRead=True,#ExclusiveStartKey='',
                                                                 FilterExpression=Attr("CrossAuditRole").ne('NotFound') & Attr("Scout2dataS3key").ne('N/A'))
        else:                                              
            accounts_list_table_scan = accounts_list_table.scan(Select='ALL_ATTRIBUTES',Limit=5,ExclusiveStartKey={'AccountID':str(get_evaluated_key['Parameter']['Value'])},
                                                            FilterExpression=Attr("CrossAuditRole").ne('NotFound') & Attr("Scout2dataS3key").ne('N/A'))
        accounts_list_table_scan_ext = accounts_list_table_scan['Items']
        #print(accounts_list_table_scan)
        s3_table = dynamodb_resource.Table(verifyLogTable('security-audit-S3',update_table_primarykey,update_table_sort_key))
        ac_s3_info={}
        #############################################################   
            #DOWNLOADING FINDINGS DATA FROM S3BUCKET
        #############################################################
        for key in accounts_list_table_scan_ext:
            print("Scanning for:"+ key['AccountID'] +':'+key['Alias'] )
            try:
                #print("-->Downloading Account S3Key:--",key['Scout2dataS3key'])
                if key['AccountID']=='478226638351':
                    s3_data_file=key['AccountID']+'/'+service+'/'+s3_update_date+'/aws_config.js' 
                else:
                    s3_data_file=key['AccountID']+'/'+service+'/'+s3_update_date+'/'+'aws_config-'+key['Alias']+'.js'
                s3.Bucket(BUCKET_NAME).download_file(s3_data_file, '/tmp/findings.js')
                with open("/tmp/findings.js", 'rt') as f:
                    next(f)
                    content = f.read()
                    data = json.loads(content)
            except Exception as e:
                alrt+='AccountName:  {} \n '.format(str(key['Alias']))
                print("-----Unable to read Scout2 Data for the account:--"+ key['AccountID'] +':'+key['Name'])
                print("-----Moving to next Account Key-------X")
                continue
            s3_findings = data["services"][service]["findings"]
            ac_s3_info[data["aws_account_id"]]={}
            ac_s3_info[key['AccountID']]['ReportedOn']=data["last_run"]["time"]
            scout2_reportdate=data["last_run"]["time"]
            reportdate=(parser.isoparse(scout2_reportdate)).strftime('%Y-%m-%dT%H:%M:%SZ')
            ac_s3_info[key['AccountID']]["Scout2_Ac_Number"]=data["aws_account_id"]
            ################################################################## 
            #  PARSING DATA FILE FOR THE SERVICE 'S3' FOR EACH SCOUT2S3-RULE
            ##################################################################
            for key_s3, key_value in s3_findings.items():
                s3_config_findings = data["services"][service]["findings"][key_s3]
                #print("------------->Searching for:-",s3_config_findings["dashboard_name"],  key_s3)
                if s3_config_findings["flagged_items"] >= 1:
                    items_list_found = s3_config_findings["items"]
                    #print("-------------------->Items Found As:--",   len(items_list_found))
                    ac_s3_info[data["aws_account_id"]][key_s3]={}
                    ac_s3_info[key['AccountID']][key_s3]["checked_items"] = s3_config_findings['checked_items']
                    ac_s3_info[key['AccountID']][key_s3]["flagged_items_count"] = s3_config_findings['flagged_items']
                    ac_s3_info[key['AccountID']][key_s3]["level"] = s3_config_findings['level']
                    ac_s3_info[key['AccountID']][key_s3]["dashboard_name"] = s3_config_findings['dashboard_name']
                    ac_s3_info[key['AccountID']][key_s3]["description"] = s3_config_findings['description']
                    ac_s3_info[key['AccountID']][key_s3]["rationale"] = s3_config_findings['rationale']
                    ac_s3_info[key['AccountID']][key_s3]["service"] = s3_config_findings['service']
                    ac_s3_info[key['AccountID']][key_s3]["Found_List"]=[]
                    ac_s3_info[key['AccountID']][key_s3]["Found_Details"] = {}
                    strip_id = re.findall(r"(?<=s\.).*?(?=\.)", str(items_list_found))
                    #print("Stripped As--",  strip_id)
                    found_info=data["services"][service]["buckets"]
                    for item in strip_id:
                        try:
                            ac_s3_info[key['AccountID']][key_s3]["Found_List"].append(found_info[item]['name'])
                            ac_s3_info[key['AccountID']][key_s3]["Found_Details"][found_info[item]['name']]={}
                            ac_s3_info[key['AccountID']][key_s3]["Found_Details"][found_info[item]['name']]=found_info[item]
                        except KeyError:
                            continue
                    #print("  ------------------------>>SUMMARRY OF ",           key_s3)
                    #print(ac_s3_info[key['AccountID']][key_s3]) 
                    #print("-------------------------->Writing Data to Dynamodb")
                    writedatatodynamodb(s3_table,ac_s3_info[key['AccountID']][key_s3],key,key_s3,reportdate,running_date,alrt,'Scout2')                  
                else:  # DELETING THE RULE IF FOUND ITEMS 0
                    #print("-------->Nothing foud for rule:--"+   key_s3+"X-On-X"+  key['AccountID'])
                    try:
                        #print("--------------Deleting item if it exists from Dynamodb-------------------")
                        response=s3_table.delete_item (Key={'Accountid':key['AccountID'],'Rulename':key_s3})
                    except Exception as err:
                        raise err
            ##################################################################                  
            ##      FINDINGS THE WEBSITE ENABLED BUCKETS       ##############
            ##################################################################
            key_s3="s3-bucket-website-enabled"
            print("***Searching for",key_s3 )
            s3_filter_findings = data["services"][service]["filters"][key_s3]
            if s3_filter_findings["flagged_items"] >= 1:
                ac_s3_info[data["aws_account_id"]][key_s3]={}
                ac_s3_info[key['AccountID']][key_s3]["checked_items"] = s3_filter_findings["checked_items"]
                ac_s3_info[key['AccountID']][key_s3]["flagged_items_count"] = s3_filter_findings["flagged_items"]
                ac_s3_info[key['AccountID']][key_s3]["level"] = s3_filter_findings["level"] if s3_filter_findings["level"] else "warning"
                ac_s3_info[key['AccountID']][key_s3]["dashboard_name"] = s3_filter_findings["dashboard_name"]
                ac_s3_info[key['AccountID']][key_s3]["description"] = s3_filter_findings["description"]
                ac_s3_info[key['AccountID']][key_s3]["rationale"] = s3_filter_findings["rationale"]
                ac_s3_info[key['AccountID']][key_s3]["service"] = s3_filter_findings["service"]
                items_public_found=s3_filter_findings["items"]
                ac_s3_info[key['AccountID']][key_s3]["Found_List"]=[]
                ac_s3_info[key['AccountID']][key_s3]["Found_Details"] = {}
                found_info=data["services"][service]["buckets"]
                strip_id = re.findall(r"(?<=s\.).*?(?=\.)", str(items_public_found))
                print("public website Check Items",items_public_found )
                for item in strip_id:
                    try:
                        ac_s3_info[key['AccountID']][key_s3]["Found_List"].append(found_info[item]['name'])
                        ac_s3_info[key['AccountID']][key_s3]["Found_Details"][found_info[item]['name']]={}
                        ac_s3_info[key['AccountID']][key_s3]["Found_Details"][found_info[item]['name']]=found_info[item]  
                    except KeyError:
                        print("Unable to find key for",item )
                        continue
                print("  ------------------------>>SUMMARRY OF ")
                print('key_s3:-',   ac_s3_info[key['AccountID']][key_s3]) 
                print("-------------------------->Writing Data to Dynamodb")
                writedatatodynamodb(s3_table,ac_s3_info[key['AccountID']][key_s3],key,key_s3,reportdate,running_date,alrt,'Scout2')                               
            else:           # DELETING THE RULE IF FOUND ITEMS 0
                print("-------->Nothing foud for rule:--"+   key_s3+"X-On-X"+  key['AccountID'])
                try:
                    print("--------------Deleting item if it exists from Dynamodb-------------------")
                    response=s3_table.delete_item (Key={'Accountid':key['AccountID'],'Rulename':key_s3})
                except Exception as err:
                    raise err
            f.close()
            print("-------------------->>FINAL SUMMARRY",   ac_s3_info[key['AccountID']])
            cleardict(data)
        #############################################################   
            #CHECK/STORE THE LASTEVALUATEDKEY FROM PARAMATER STORE
        #############################################################
        if 'LastEvaluatedKey' in accounts_list_table_scan:
            print("----------Updating Last Evaluated Key as",accounts_list_table_scan['LastEvaluatedKey'])
            LastEvaluatedKey=accounts_list_table_scan['LastEvaluatedKey']['AccountID']
            ClientSSM.put_parameter(Name='Scout2-S3-Startkey',Description='s3LastEvaluatedKey',Value=LastEvaluatedKey,Type='String',Overwrite=True)
            print(LastEvaluatedKey)
        else:
            print("---------->LastEvaluatedKey found as null_Updating key as Null and finished all accounts")
            LastEvaluatedKey='Null'
            ClientSSM.put_parameter(Name='Scout2-S3-Startkey',Description='s3LastEvaluatedKey',Value=LastEvaluatedKey,Type='String',Overwrite=True)
    except Exception as error:
        alrt+='\nFailed Lambda IAM Reporting Function -arn:aws:lambda:us-east-2:478226638351:function:security-audit-S3:  {} \n '.format(str(running_date+":Error"+error))
        raise error
    if alrt:
        alrt+='\nMissing Report As of:  {} \n '.format(str(running_date))
        alrt+='\nPossible Reason:  {} \n '.format(str("Please check the bucket 'ue2-scout2-prod-history' for missing report with accountid/date and for more details about this account check dynamodb table 'awsaccounts-crossaccountrole-list'"))
        publish_msg_security_team("AWS SCOUT2 Missing Report for Accounts Attached", alrt)  
    return "success"
def clearlist(slis):  # clearing list
    slis[:] = []
def cleardict(sdict):  # clearing dictonary
    sdict.clear()
################################################################## 
    #   CONVERTING TIMEZONE IN TO CHICAGO/US-CENTRAL
##################################################################
def timeconvertertoCST(srctime):
    totimezone = 'US/Central'
    curtime = srctime.strftime("%m-%d-%Y %I:%M:%S %p")
    from_zone = tz.tzutc()
    to_zone = tz.gettz(totimezone)
    utc = datetime.strptime(curtime, '%m-%d-%Y %I:%M:%S %p')
    utc = utc.replace(tzinfo=from_zone)
    tocentral = utc.astimezone(to_zone).strftime("%m-%d-%Y %I:%M:%S %p")
    return tocentral
def publish_msg_security_team(Subject, Message):
    try:
        print("sending sns")
        sns_client.publish(TopicArn='arn:aws:sns:us-east-2:478226638351:AWS_Security_Scan_Alerts', Message=Message, Subject=Subject, MessageStructure='string')
        #sns_client.publish(TopicArn='arn:aws:sns:us-east-2:478226638351:test_sns_poc_personal', Message=Message, Subject=Subject, MessageStructure='string')
    except Exception as err:
        print (error)   
################################################################## 
    #   CREATING NEW TABLE IF UNFOUND WITH NAME 
##################################################################
def verifyLogTable(tablename,primarykey,sortkey):
    """Verifies if the table name provided is exists/not
    Returns:
        The real table name
        TYPE: String
    """
    client = boto3.client('dynamodb')
    resource = boto3.resource('dynamodb')
    table = tablename

    response = client.list_tables()
    tableFound = False
    for n, _ in enumerate(response['TableNames']):
        if table in response['TableNames'][n]:
            table = response['TableNames'][n]
            tableFound = True

    if not tableFound:
        # Table not created in CFn, let's check exact name or create it
        try:
            result = client.describe_table(TableName=table)
        except:
            # Table does not exist, create it
            newtable = resource.create_table(
                TableName=table,
                KeySchema=[
                     {
                        'AttributeName': primarykey,
                        'KeyType': 'HASH',
                     },
                     {   ##Hash is primary key 
                        'AttributeName': sortkey, 
                        'KeyType': 'RANGE',  
                     },
                ],   ## Range is sortkey 
                AttributeDefinitions=[
                    {   'AttributeName': primarykey, 
                        'AttributeType': 'S',
                    },
                    {   'AttributeName': sortkey, 
                        'AttributeType': 'S',
                    },
                ],
                ProvisionedThroughput={'ReadCapacityUnits': 15, 'WriteCapacityUnits': 15}
            )
            # Wait for table creation
            newtable.meta.client.get_waiter('table_exists').wait(TableName=table)
    return table
################################################################## 
    #   CLEANING THE EMPTY VALUES IN DICTONARY
##################################################################
def clean_empty(d):
    if not isinstance(d, (dict, list)):
        return d
    if isinstance(d, list):
        return [v for v in (clean_empty(v) for v in d) if v]
    return {k: v for k, v in ((k, clean_empty(v)) for k, v in d.items()) if v}
################################################################## 
    #   WRITING DATA TO DYNAMODB FROM COLLECTED ITERATIONS
##################################################################
def writedatatodynamodb(update_table,service_finding_info,key,rulename,reportdate,running_date,alrt,ReportedFrom):
        try:
            update_table.put_item ( 
                Item={
                    'Accountid':key['AccountID'],
                    'Rulename':rulename,
                    'Aliasname':key['Alias'],
                    'E-mail':key['Email'],
                    'Risklevel':service_finding_info['level'],
                    'Lastexecuteddate':str(running_date),
                    'Foundeddate':str(reportdate),
                    'Rationale':service_finding_info['rationale'],
                    'Description':service_finding_info["description"],
                    'Totalcheckeditems':str(service_finding_info['checked_items']),
                    'Flaggeditemslist':service_finding_info['Found_List'],
                    'Flaggeditemscount':str(service_finding_info['flagged_items_count']),
                    'Detailedinfo':clean_empty(service_finding_info['Found_Details']),
                    'Service':str(service_finding_info['service']+':'+service_finding_info['dashboard_name']),
                    'Managedby':key['Managedby'],
                    'Department':key['Department'],
                    'Division':key['Division'],
                    'Type':key['Type'],
                    'Techowner':key['Techowner'],
                    'Dataclassification':key['Dataclassification'],
                    'Businessowner':key['Businessowner'],
                    'Reportedby':ReportedFrom,
                    }
                )
        except Exception as e:
            raise e
            alrt+=':Error writing data for the rule  {} \n '.format(str(rulename))
            print("Error writing data to dynamdodb")
################################################################## 
    #                END OF AWS-S3 GAME
##################################################################