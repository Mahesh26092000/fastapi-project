from fastapi import FastAPI, Depends, Response, status, HTTPException

from pydantic import BaseModel
import models
from database import engine,SessionLocal
from sqlalchemy.orm import Session

app = FastAPI()

models.Base.metadata.create_all(engine)

class Users(BaseModel):
	adhaar_number: int
	keyforkivy: str
	activation_code: str

class kivyresponse(BaseModel):
	keyforkivy: str
	
	class Config():
		orm_mode= True




def get_db():
	db= SessionLocal()
	try:
		yield db
	finally:
		db.close()

@app.post('/create_new', status_code=201)
def create(request: Users, db : Session = Depends(get_db)):
	user = models.Useraccounts(adhaar_number = request.adhaar_number, keyforkivy = request.keyforkivy, activation_code= request.activation_code)
	db.add(user)
	db.commit()
	db.refresh(user)
	return user


@app.get('/userlist')
def all(db: Session = Depends(get_db)):
	userlist = db.query(models.Useraccounts).all()
	return userlist


@app.get('/uniqueuserlist/{activation_code}',status_code=200, response_model=kivyresponse)
def show(activation_code,response: Response, db: Session = Depends(get_db)):
	user = db.query(models.Useraccounts).filter(models.Useraccounts.activation_code == activation_code).first()
	if not user:
		response.status_code = status.HTTP_404_NOT_FOUND
		return {'detail': f'activation code {activation_code} is not available'}
	return user


@app.delete('/userdelete/{id}',status_code=status.HTTP_204_NO_CONTENT)
def destroy(id, db: Session = Depends(get_db)):
	user = db.query(models.Useraccounts).filter(models.Useraccounts.id == id)
	if not user.first():
		raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail= "no such user exist")
	user.delete(synchronize_session=False)
	db.commit()
	return "done"


@app.put('/userlist/{id}',status_code=202)
def update(id, request: Users, db: Session = Depends(get_db)):
	userupdate = db.query(models.Useraccounts).filter(models.Useraccounts.id == id)
	if not userupdate.first():
		raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail= "no such user exist")
	userupdate.update(request.dict())
	db.commit()
	return 'updated successfully'
