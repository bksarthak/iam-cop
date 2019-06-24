import json
import csv
import boto3



def lambda_handler(event, context):

    account_number = event['account']
    user_Id = event['detail']['userIdentity']['arn']
    user_agent = event['detail']['userAgent']
    event_time = event['detail']['eventTime']

    policy_body = event['detail']['requestParameters']['policyDocument']
    result = evaluate_policy(policy_body)
    return result

#function to evaluate the policy statements
def evaluate_policy(policy):
    with open('denied_actions.csv','r') as file:
        reader = csv.reader(file,delimiter=',')
        deniedActions_list = list(reader)
        #print (deniedActions_list[0])
    for statements in policy["Statement"]: #loop through each statement of the policy
        if statements["Effect"] == 'Allow':   # evaluate only if the statement action is Allow
            policy_actions = list_actions(statements)
            violating_actions = list(set(deniedActions_list[0]).intersection(set(policy_actions)))
    return violating_actions

#function to return a list of actions for each statement
def list_actions(statement):
    action_list=[]
    for actions in statement["Action"]:
        action_list.append(actions)
    return action_list
