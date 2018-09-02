from cabby import create_client
from stix.core import STIXPackage, STIXHeader
from elasticsearch import Elasticsearch
from datetime import date, timedelta
import glob
import datetime
import pytz
import argparse
import os
import warnings
import sys

warnings.filterwarnings("ignore")

def _setup_argument_parser():
    parser = argparse.ArgumentParser(
        description='A tool for fetching `ANOMALI` '
        			'limo threat feed collection '
        			'and save them to ElasticSearch'
    )

    parser.add_argument('-d', '--days', help='Define the timedelta in days.'
    					,type=int,default=1)
    parser.add_argument('-u', '--username', help='Define the username.',
    					default='guest')
    parser.add_argument('-p', '--password', help='Define the password.',
    					default='guest')
    parser.add_argument('-e', '--es', help='Define the elasticsearch host.',
    					default='localhost')
    parser.add_argument('-l', '--port', help='Define the elasticsearch port.',
    					type=int,default=9200)
    parser.add_argument('-i', '--index', help='Define the elsticsearch index.',
    					default='taxii_anomali')

    return parser

def process_arguments():
    args = _setup_argument_parser().parse_args()
    return args

def begin_date(day):
	b = datetime.datetime.now() - timedelta(days=int(day))
	timezone = pytz.timezone("Europe/Athens")
	b_date = timezone.localize(b)
	
	return b_date

def end_date():
	e = datetime.datetime.now()
	timezone = pytz.timezone("Europe/Athens")
	e_date = timezone.localize(e)
	
	return e_date

def main():
	args=process_arguments()
	
	client = create_client('limo.anomali.com',\
		use_https=True,\
		discovery_path='/api/v1/taxii/taxii-discovery-service/')

	client.set_auth(username=args.username, password=args.password)

	collections = client.get_collections(uri=''
		'https://limo.anomali.com/api/v1/taxii/collection_management/')

	for c in collections:

		print "[*]-Fetching collection name: {} ".format(c.name)

		content_blocks = client.poll(collection_name=c.name,\
			begin_date=begin_date(args.days),\
			end_date=end_date())

		for block in content_blocks:
			with open(c.name+'.xml', 'wb') as file_handle:
				file_handle.write(block.content)

	es=Elasticsearch([{'host':args.es,'port':args.port}])
	
	try:
		if es.ping():
			print "\n[*]-Connection with ES was successful."
	except ValueError:
		print "\n[*]-Connection with ES was failed."
		sys.exit(-1)

	try:
		if es.indices.exists(args.index):
			re=es.indices.delete(index=args.index, ignore=[400, 404])
			print "[*]-Deleting {} index... Status: {}".format(args.index,re.get('acknowledged'))
	except:
		print "[*]-Something was wrong with the deletion of the index {}.".format(args.index)
		sys.exit(-1)

	document={}

	print "[*]-Creating {} index...".format(args.index)
	res = es.indices.create(index = args.index, body = document)
	if res:
		print "[*]-Index {} created successully... Status: {}".format(args.index,res.get('acknowledged'))
	else:
		print "[*]-Something went wrong with the creation of the index {}.".format(args.index)
		sys.exit(-1)

	xml_files = glob.glob("*.xml")

	for xml in xml_files:
		pkg=STIXPackage.from_xml(xml)
		pkg_dict=pkg.to_dict()

		for v in pkg_dict.get('indicators'):
			description=v.get('description').split(';')
			Produced_Time=v.get('producer').get('time').get('produced_time')
			description=v.get('description').split(';')
			State=description[3].split(':')
			Org=description[4].split(':')
			Source=description[5].split(':')
			Indtitle=v.get('title').strip(' ').split(':')
			IndicatorType=','.join(ind.get('value') for ind in v.get('indicator_types'))
			Severity=''.join(v.get('observable').get('keywords'))
			IPAddress=v.get('observable').get('object').get('properties').get('address_value')
			Value=v.get('observable').get('object').get('properties').get('value')
			Confidence=v.get('confidence').get('value').get('value')
				
			document={
				'Value':Value,
				'IPAddress':IPAddress,
				'Category':Indtitle[0],
				'Indicator_Type' : IndicatorType,
				'Severity':Severity,
				'Confidence':Confidence,
				'State':State[1],
				'Organisation':Org[1],
				'Source':Source[1],
				'Produced_Time':Produced_Time
			}

			es.index(index=args.index,doc_type='anomali_threat_feed_free',body=document)

	es.indices.refresh(index=args.index)
	total_res = es.search(index=args.index)
	print "[*]-{} documents have been saved.".format(total_res['hits']['total'])

if __name__ == '__main__':
	main()