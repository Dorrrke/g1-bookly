package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Dorrrke/g1-bookly/internal/domain/models"
	mock_server "github.com/Dorrrke/g1-bookly/moks"

	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestGetUsersHandler(t *testing.T) {
	var srv Server
	r := gin.Default()
	r.GET("/getusers", srv.GetUsersHandler)
	httpSrv := httptest.NewServer(r)

	type want struct {
		code  int
		users string
	}
	type test struct {
		name    string
		request string
		method  string
		users   []models.User
		err     error
		want    want
	}
	tests := []test{
		{
			name:    "Test 'GetUserHendler' #1; Default call",
			request: "/getusers",
			method:  http.MethodGet,
			users: []models.User{
				{
					UID:      1,
					Name:     "Vitya",
					Login:    "login1",
					Password: "pass1",
				},
				{
					UID:      2,
					Name:     "Sasha",
					Login:    "sasha2000",
					Password: "qwerty1234",
				},
			},
			want: want{
				code:  http.StatusOK,
				users: `[{"uId":1,"name":"Vitya","login":"login1","password":"pass1"},{"uId":2,"name":"Sasha","login":"sasha2000","password":"qwerty1234"}]`,
			},
		},
		{
			name:    "Test 'GetUserHendler' #2; Error call",
			request: "/getusers",
			method:  http.MethodGet,
			users:   nil,
			err:     errors.New("test error"),
			want: want{
				code:  http.StatusInternalServerError,
				users: `{"error":"test error"}`,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := mock_server.NewMockRepository(ctrl)
			defer ctrl.Finish()
			m.EXPECT().GetAllUsers().Return(tc.users, tc.err)
			srv.Db = m
			req := resty.New().R()
			req.Method = tc.method
			req.URL = httpSrv.URL + tc.request
			resp, err := req.Send()
			assert.NoError(t, err)
			assert.Equal(t, tc.want.users, string(resp.Body()))
			assert.Equal(t, tc.want.code, resp.StatusCode())
		})
	}
	httpSrv.Close()
}

func TestRegisterHandler(t *testing.T) {
	var srv Server
	r := gin.Default()
	r.POST("/register", srv.RegisterHandler)
	httpSrv := httptest.NewServer(r)

	type want struct {
		code   int
		answer string
	}
	type test struct {
		name    string
		request string
		method  string
		user    string
		err     any
		errCall bool
		dbFlag  bool
		want    want
	}
	tests := []test{
		{
			name:    "Test 'RegisterHandler' #1; Default call",
			request: "/register",
			method:  http.MethodPost,
			user:    `{"uId":1,"name":"Vitya","login":"login1","password":"pass1"}`,
			err:     nil,
			dbFlag:  true,
			want: want{
				code:   http.StatusOK,
				answer: "was saved",
			},
		},
		{
			name:    "Test 'RegisterHandler' #2; BadRequest call",
			request: "/register",
			method:  http.MethodPost,
			user:    "",
			err:     nil,
			errCall: true,
			dbFlag:  false,
			want: want{
				code: http.StatusBadRequest,
			},
		},
		{
			name:    "Test 'RegisterHandler' #3; Conflict call",
			request: "/register",
			method:  http.MethodPost,
			user:    `{"uId":1,"name":"Vitya","login":"login1","password":"pass1"}`,
			err:     errors.New(`ERROR`),
			errCall: true,
			dbFlag:  true,
			want: want{
				code:   http.StatusInternalServerError,
				answer: `{"error":"ERROR"}`,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.dbFlag {
				ctrl := gomock.NewController(t)
				m := mock_server.NewMockRepository(ctrl)
				defer ctrl.Finish()
				m.EXPECT().InsertUser(gomock.Any()).Return(1, tc.err)
				srv.Db = m
			}
			req := resty.New().R()
			req.Method = tc.method
			req.Body = tc.user
			req.URL = httpSrv.URL + tc.request
			resp, err := req.Send()
			assert.NoError(t, err)
			assert.Equal(t, tc.want.code, resp.StatusCode())
			if tc.errCall {
				if tc.want.answer != "" {
					assert.Equal(t, tc.want.answer, string(resp.Body()))
					return
				}
			} else {
				assert.Contains(t, string(resp.Body()), tc.want.answer)
				assert.NotEmpty(t, resp.Header().Get("Authorization"))
				_, err = getUID(string(resp.Header().Get("Authorization")))
				assert.NoError(t, err)
			}
		})
	}
	httpSrv.Close()
}
