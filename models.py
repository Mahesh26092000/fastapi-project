from sqlalchemy import Column, Integer, String
from database import Base


class Useraccounts(Base):
	__tablename__ ='customerstoactivatecodes'
	id = Column(Integer, primary_key=True, index=True)
	adhaar_number = Column(Integer)
	keyforkivy = Column(String)
	activation_code = Column(String)