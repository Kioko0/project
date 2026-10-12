import os
from pymongo import MongoClient
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

def get_db():
    client = MongoClient(
        os.getenv('MONGO_URI', 'mongodb://mongodb:27017/'),
        serverSelectionTimeoutMS=10000,
    )
    return client['vulnerability_system']

def store_records(scored_records):
    db  = get_db()
    col = db['scored_vulnerabilities']
    for rec in scored_records:
        rec['stored_at'] = datetime.utcnow().isoformat()
        col.update_one(
            {'cve_id': rec['cve_id'], 'host_ip': rec['host_ip']},
            {'$set': rec},
            upsert=True
        )
    print(f'[DB] {len(scored_records)} records stored in MongoDB.')

def get_all_scored():
    db  = get_db()
    col = db['scored_vulnerabilities']
    return list(col.find({}, {'_id': 0}).sort('risk_score', -1))

def get_by_segment(segment):
    db  = get_db()
    col = db['scored_vulnerabilities']
    return list(col.find({'segment': segment}, {'_id': 0}).sort('risk_score', -1))

def has_results():
    db  = get_db()
    col = db['scored_vulnerabilities']
    return col.count_documents({}) > 0

if __name__ == '__main__':
    records = get_all_scored()
    print(f'[DB] {len(records)} records in database.')
    if records:
        print(records[0])
