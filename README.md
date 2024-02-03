# D-auth

git clone https://github.com/haidyeed/D-auth.git

cp .env.example .env
composer install
php artisan key:generate
CREATE DATABASE d_auth (via mysql command)
php artisan migrate
php artisan db:seed
php artisan serve --port=9000

note : all users passwords are set to 12345678
User login : url /login any user name or email with password = 12345678

_________________________________________________

git clone https://github.com/haidyeed/D-note.git

cp .env.example .env
composer install
php artisan key:generate
CREATE DATABASE d_note (via mysql command)
php artisan migrate
php artisan db:seed
php artisan serve --port=8000

__________________________________________________

Api Documentation : I used Rakutentech package
http://127.0.0.1:8000/request-docs
&
http://127.0.0.1:9000/request-docs

___________________________________________________

My logged time approx.. 
authentication feature: about 2 hrs
tests: about 1 hr
api documentaion: less than an hour
notes feature: about 2 hrs
microservices communication: about 2 hrs

____________________________________________________

apis :
auth-microservice:
method: POST
url: http://127.0.0.1:9000/api/register
body: {
    "email":"test@mail.com",
    "password":"12345678",
    "password_confirmation":"12345678",
    "name":"test"
}
response: {
    "success": "Account successfully registered.",
    "user": {
        "name": "test",
        "email": "test@mail.com",
        "updated_at": "2024-02-03T16:18:32.000000Z",
        "created_at": "2024-02-03T16:18:32.000000Z",
        "id": 224
    }
}
_______________
method: POST
url: http://127.0.0.1:9000/api/login
body: {
    "email":"test@mail.com",
    "password":"12345678",
    "password_confirmation":"12345678",
    "name":"test"
}
response:{
    "success": {
        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiI5YjNkNmVjOC1iMWRmLTQ5NmItODgzYS01ZmQxNDY4ZTg2OWIiLCJqdGkiOiI0MjhmOGQ1MDU4OWUzOGNmM2ZlYjA3MjY1NzVlMjZmNmZmYTQ3ZDUyZTkxNzkyMmYwN2VmMjM3ZTYzOTUzNmE1MjI4MGMwZDg4YjU1YjcwZCIsImlhdCI6MTcwNjk2OTU4MS4yMDU0MTQsIm5iZiI6MTcwNjk2OTU4MS4yMDU0MTYsImV4cCI6MTczODU5MTk4MS4xOTI3NTQsInN1YiI6IjMiLCJzY29wZXMiOltdfQ.fno77o0-Rwztv9sATvGwvSup2yLXPHvLWLAPjzx0s5ipquDKFwVwrKvzOxz3ZXgkcFqNdiAZjyCJbuRJ41LwrCmqZFr64BLmoVfLL915fAH65uTzmqdkA3MroBAthebeb76OtianRUenLnjbmedrqDF3Q7Te8AK0HJjePLhizw7f5x6kCNLDojMrzzPKcMjXrRL_L52qhpSELVrshg8JV0tv6rw_fzdZsyl96J8PcX5IW_68TW4GvGohiTBRXkLkvYpI7A7EekYD85V3Bw1Yt3p2PWZ55jwlIit_EbDE87pYiWOc2hACG0hGNjO0DlQdTFbHbZLH0E7nVE3LzahfaPDuco_oqSd0Fmur3Ei6hP_6VGz0HmsAwTuU3KhzCQLILcSUvG37TG2_Pa71r3cdZSduDpUEYznffMCX7jtCqwxQQBMny2iWYthNq3WfBCLzpkUoxJylbSD4MYtXV7NO1rb__UNd_95WtvRh21ikYO-C5a6Qs6vWPs5CyDIEa4XN_MStWLm_W75RcyNe93qVIA3Gc98jfpoB4h4i5tnGRLuI0argzr58c8j2DVXwteM4YsPmIO6rI27i3bdd8THZM71V3TdYbC5QwRTR5X63igsjWuTOMDx2TXUx2TDvYNZc99JyRD0QFWADn3nhiGOcL3NzfAnrwLnUQsz_xiE5Dv0"
    },
    "user": {
        "id": 3,
        "name": "test test",
        "email": "test@mail.com",
        "email_verified_at": null,
        "created_at": "2024-02-02T17:18:13.000000Z",
        "updated_at": "2024-02-02T17:18:13.000000Z"
    }
}
__________________________
note-microservice:
notes
- user id can be added directly by communication with auth microservice & not be added into api request (this has been declared in code comments)

- All note-microservices apis must be authorized with bearer token coming from auth login api

- All listed responses are in success case response, in case on any error response will be changed accordingly

method: POST
url: http://127.0.0.1:8000/api/notes
body: {
    "title":"title",
    "content":"content for this note",
    "user_id":1
}
response:{
    "success": true,
    "message": "a new note has been added successfully",
    "data": {
        "title": "title",
        "content": "content for this note",
        "user_id": 1,
        "updated_at": "2024-02-03T15:20:20.000000Z",
        "created_at": "2024-02-03T15:20:20.000000Z",
        "id": 3
    }
}
_________________________________
method: GET
url: http://127.0.0.1:8000/api/notes
body: 
response: {
    "success": true,
    "message": "a list of all notes",
    "data": {
        "current_page": 1,
        "data": [
            {
                "id": 3,
                "title": "title",
                "content": "content for this note",
                "user_id": 3,
                "created_at": "2024-02-03T15:20:20.000000Z",
                "updated_at": "2024-02-03T15:20:20.000000Z"
            },
            {
                "id": 2,
                "title": "title",
                "content": "content for this note",
                "user_id": 1,
                "created_at": "2024-02-02T23:16:36.000000Z",
                "updated_at": "2024-02-02T23:16:36.000000Z"
            }
        ],
        "first_page_url": "http://127.0.0.1:8000/api/notes?notepage=1",
        "from": 1,
        "last_page": 1,
        "last_page_url": "http://127.0.0.1:8000/api/notes?notepage=1",
        "links": [
            {
                "url": null,
                "label": "&laquo; Previous",
                "active": false
            },
            {
                "url": "http://127.0.0.1:8000/api/notes?notepage=1",
                "label": "1",
                "active": true
            },
            {
                "url": null,
                "label": "Next &raquo;",
                "active": false
            }
        ],
        "next_page_url": null,
        "path": "http://127.0.0.1:8000/api/notes",
        "per_page": 10,
        "prev_page_url": null,
        "to": 2,
        "total": 2
    }
}
___________________
method: GET
url: http://127.0.0.1:8000/api/notes/2
body: 
response: {
    "success": true,
    "message": "note",
    "data": {
        "id": 2,
        "title": "title",
        "content": "content for this note",
        "user_id": 1,
        "created_at": "2024-02-02T23:16:36.000000Z",
        "updated_at": "2024-02-02T23:16:36.000000Z"
    }
}
____________________
note: in edit method we can edit one or more fields
method: PUT
url: http://127.0.0.1:8000/api/notes/2
body: {
    "title":"another name"
}
response: {
    "success": true,
    "message": "note updated successfully",
    "data": {
        "id": 2,
        "title": "another name",
        "content": "content for this note",
        "user_id": 1,
        "created_at": "2024-02-02T23:16:36.000000Z",
        "updated_at": "2024-02-03T16:32:01.000000Z"
    }
}
_________________
method: DELETE
url: http://127.0.0.1:8000/api/notes/1
body: 
response: {
    "success": true,
    "message": "note deleted successfully"
}
__________________