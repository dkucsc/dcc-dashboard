#queries using Elasticsearch using python

# This query works with es5
# 	{
# 		 "query": { 
# 			  "bool": { 
# 					"must": [
# 						 {"term": { "flags.tumor_sequence" : True}},
# 						 {"term": { "flags.normal_sequence" : True}}
# 			  ]}
# 		 }
# 	}

from elasticsearch import Elasticsearch
import json
from itertools import combinations

es_host = 'localhost:9200'

es = Elasticsearch([es_host])

es_name_query = [
   "All normal and tumor fastq exist.",
   "Fastq normal and tumor exist, no alignment.",
   "Alignment normal and tumor exist, no somatic.",
   "All flags are true. All documents exist."
]

flags = [
	"tumor_sequence",
	"normal_alignment_qc_report",
	"tumor_somatic_variants",
	"tumor_alignment",
	"normal_sequence",
	"tumor_alignment_qc_report",
	"normal_alignment",
	"normal_sequence_qc_report",
	"tumor_rnaseq_variants",
	"normal_rnaseq_variants",
	"normal_germline_variants",
	"tumor_sequence_qc_report"
]

# IDEA A: This looks at all combinations of flags. Queries look at all flags and their boolean values.
# Each donor is on the bar chart only once.

# es_queries = []
# output = sum([map(list, combinations(flags, i)) for i in range(len(flags) + 1)], [])
# termholder = []
# query_num = 0
# with open("data.json", 'w') as outfile:
# 	outfile.write('[')
# 	addingcommas = False
# 	for item in output:
# 		termholder = []
# 		query_num = query_num + 1
# 
# 		es_name = []
# 		for term in item:
# 			termholder.append('{"term": {"flags.'+term+'" : true}}')
# 			es_name.append(term)
# 			for flag in flags:
# 				if flag not in item:
# 					termholder.append('{"term": {"flags.'+flag+'" : false}}')
# 		es_queries.append('{"query": { "bool": { "must": '+str(termholder).replace("'", "")+'}}}')
# 
# 		response = es.search(index="analysis_index", body=es_queries[query_num-1])
# 
# 		#print("count: "+str(response['hits']['total']))
# 		count = response['hits']['total']
# 		#print("\n")
# 		if (count >0 ):
# 			if (addingcommas):
# 				outfile.write(', ')
# 			else:
# 				addingcommas = True
# 			outfile.write('{"Label": "'+str(es_name).replace("'", "").replace("[]", "total number of results").replace("[", "").replace("]", "")+'", "Count": '+str(count)+'}')
# 	outfile.write(']')

##############################

# IDEA B 
# A donor could be on the bar chart multiple times. ie: item with alignment done also has fastq done
# sample queries

# can add more fields if wanted to item_to_query
item_to_query = [
	["tumor_sequence", "normal_sequence"],
	["tumor_sequence_qc_report", "normal_sequence_qc_report"],
	["tumor_alignment", "normal_alignment"],
	["tumor_alignment_qc_report", "normal_alignment_qc_report"],
	["tumor_somatic_variants", "normal_germline_variants"],
	["tumor_rnaseq_variants", "normal_rnaseq_variants"]
]
es_queries = []
termholder = []

query_num = 0
with open("data.json", 'w') as outfile:
	outfile.write('[')
	addingcommas = False
	for item in item_to_query:
		termholder = []
		query_num = query_num + 1
		es_name = []
		for term in item:
			termholder.append('{"term": {"flags.'+term+'" : true}}')
			es_name.append(term)
			
		es_queries.append('{"query": { "bool": { "must": '+str(termholder).replace("'", "")+'}}}')
		response = es.search(index="analysis_index", body=es_queries[query_num-1])

		#print("count: "+str(response['hits']['total']))
		count = response['hits']['total']
		#print("\n")
		#if (count >0 ):
		if (addingcommas):
			outfile.write(', ')
		else:
			addingcommas = True
		outfile.write('{"Label": "'+str(es_name).replace("'", "").replace("[", "").replace("]", "")+' available", "Count": '+str(count)+'}')
	outfile.write(']')

##############################

# IDEA C
# A mix of IDEA A and B.
# donor is only on the chart once, but have given bars on charts.

