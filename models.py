from sqlalchemy import Column, Integer, String, ForeignKey, Date
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from json import JSONEncoder

Base = declarative_base()

class User(Base) :
	__tablename__ 	= 'users'
	id 				= Column(Integer, primary_key=True)
	name 			= Column(String)
	picture 		= Column(String)
	email	 		= Column(String)

class Category(Base):
	__tablename__ 		= 'categories'

	id 					= Column(Integer, primary_key=True)
	name 				= Column(String)
	items 				= relationship("Item")
	user_id		 		= Column(Integer, ForeignKey('users.id'))
	user 				= relationship(User)

	@property
	def serialize(self):
		return {
			'id': self.id, 
			'name': self.name,
			'user_id'	  : self.user_id
		}

	def __repr__(self):
		return "<Category(name='%s')>" % (self.name)

class Item(Base):
	__tablename__ 	= 'items'

	id 				= Column(Integer, primary_key=True)
	name 			= Column(String)
	description		= Column(String)
	category_id		= Column(Integer, ForeignKey('categories.id'))
	category 		= relationship(Category)
	user_id		 	= Column(Integer, ForeignKey('users.id'))
	user 			= relationship(User)
	picture			= Column(String)
	updated 		= Column(Date)
	created 		= Column(Date)

	def __repr__(self):
		return "<Item(name='%s')>" % (self.name)
		

class CustomJSONEncoder(JSONEncoder) :
	def default(self, obj) :
		try:
			if isinstance(obj, Item):
				category = ""

				if obj.category is not None :
					category = obj.category.name

				return {
					"id": obj.id, 
					"name": obj.name,
					"description": obj.description,
					"category_id" : obj.category_id,
					"user_id"	  : obj.user_id,
					"picture"		: obj.picture,
					"category" : category,
					"updated" : obj.updated.strftime('%Y-%m-%dT%H:%M:%SZ'),
					"created" : obj.created.strftime('%Y-%m-%dT%H:%M:%SZ')
				}
			if isinstance(obj, Category):
				items = []

				if obj.items is not None :
					items = obj.items

				return {
					"id": obj.id, 
					"name": obj.name,
					"user_id"	  : obj.user_id,
					"items" : items
				}
			iterable = iter(obj)
		
		except TypeError:
			pass
		else:
			return list(iterable)
		
		return JSONEncoder.default(self, obj)

