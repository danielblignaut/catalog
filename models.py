from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class Item(Base):
	__tablename__ 	= 'items'

	id 				= Column(Integer, primary_key=True)
	name 			= Column(String)
	description		= Column(String)
	category_id 	= Column(Integer, ForeignKey('categories.id'))

	def __repr__(self):
		return "<Item(name='%s')>" % (self.name)

	def serialize(self):
		return {
			'id': self.id, 
			'name': self.name,
			'description': self.description,
			'category_id' : self.category_id
		}

class Category(Base):
	__tablename__ 		= 'categories'

	id 					= Column(Integer, primary_key=True)
	name 				= Column(String)
	items 				= relationship("Item")

	def serialize(self):
		return {
			'id': self.id, 
			'name': self.name,
		}

	def __repr__(self):
		return "<Category(name='%s')>" % (self.name)
