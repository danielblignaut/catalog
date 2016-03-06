import json, models
from sqlalchemy.orm import sessionmaker, joinedload
from sqlalchemy import create_engine
engine = create_engine('postgresql:///catalog')
Session = sessionmaker(bind=engine)
Session.configure(bind=engine)
session = Session()

def populate() :
	with open('data.json') as data_file:     
		data = json.load(data_file)
		categories = []
		items = []
		for categoryJSON in data["categories"] :
			category = models.Category(name=categoryJSON["name"], user_id=categoryJSON["user_id"])
			categories.append(category)

		for itemJSON in data["items"] :
			item = models.Item(name=itemJSON["name"], description=itemJSON["description"], 
				category_id=itemJSON["category_id"], user_id=itemJSON["user_id"], 
				picture=itemJSON["picture"], updated=itemJSON['updated'], created=itemJSON['created'])
			items.append(item)

		session.add_all(categories)
		session.add_all(items);

		session.commit()