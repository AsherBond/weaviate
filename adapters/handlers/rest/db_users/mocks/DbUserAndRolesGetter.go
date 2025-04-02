//                           _       _
// __      _____  __ ___   ___  __ _| |_ ___
// \ \ /\ / / _ \/ _` \ \ / / |/ _` | __/ _ \
//  \ V  V /  __/ (_| |\ V /| | (_| | ||  __/
//   \_/\_/ \___|\__,_| \_/ |_|\__,_|\__\___|
//
//  Copyright © 2016 - 2024 Weaviate B.V. All rights reserved.
//
//  CONTACT: hello@weaviate.io
//

// Code generated by mockery v2.52.3. DO NOT EDIT.

package mocks

import (
	apikey "github.com/weaviate/weaviate/usecases/auth/authentication/apikey"
	authorization "github.com/weaviate/weaviate/usecases/auth/authorization"

	mock "github.com/stretchr/testify/mock"

	models "github.com/weaviate/weaviate/entities/models"

	time "time"
)

// DbUserAndRolesGetter is an autogenerated mock type for the DbUserAndRolesGetter type
type DbUserAndRolesGetter struct {
	mock.Mock
}

// ActivateUser provides a mock function with given fields: userId
func (_m *DbUserAndRolesGetter) ActivateUser(userId string) error {
	ret := _m.Called(userId)

	if len(ret) == 0 {
		panic("no return value specified for ActivateUser")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(userId)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CheckUserIdentifierExists provides a mock function with given fields: userIdentifier
func (_m *DbUserAndRolesGetter) CheckUserIdentifierExists(userIdentifier string) (bool, error) {
	ret := _m.Called(userIdentifier)

	if len(ret) == 0 {
		panic("no return value specified for CheckUserIdentifierExists")
	}

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (bool, error)); ok {
		return rf(userIdentifier)
	}
	if rf, ok := ret.Get(0).(func(string) bool); ok {
		r0 = rf(userIdentifier)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(userIdentifier)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CreateUser provides a mock function with given fields: userId, secureHash, userIdentifier, createdAt
func (_m *DbUserAndRolesGetter) CreateUser(userId string, secureHash string, userIdentifier string, createdAt time.Time) error {
	ret := _m.Called(userId, secureHash, userIdentifier, createdAt)

	if len(ret) == 0 {
		panic("no return value specified for CreateUser")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string, string, time.Time) error); ok {
		r0 = rf(userId, secureHash, userIdentifier, createdAt)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeactivateUser provides a mock function with given fields: userId, revokeKey
func (_m *DbUserAndRolesGetter) DeactivateUser(userId string, revokeKey bool) error {
	ret := _m.Called(userId, revokeKey)

	if len(ret) == 0 {
		panic("no return value specified for DeactivateUser")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, bool) error); ok {
		r0 = rf(userId, revokeKey)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteUser provides a mock function with given fields: userId
func (_m *DbUserAndRolesGetter) DeleteUser(userId string) error {
	ret := _m.Called(userId)

	if len(ret) == 0 {
		panic("no return value specified for DeleteUser")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(userId)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetRolesForUser provides a mock function with given fields: user, userTypes
func (_m *DbUserAndRolesGetter) GetRolesForUser(user string, userTypes models.UserTypeInput) (map[string][]authorization.Policy, error) {
	ret := _m.Called(user, userTypes)

	if len(ret) == 0 {
		panic("no return value specified for GetRolesForUser")
	}

	var r0 map[string][]authorization.Policy
	var r1 error
	if rf, ok := ret.Get(0).(func(string, models.UserTypeInput) (map[string][]authorization.Policy, error)); ok {
		return rf(user, userTypes)
	}
	if rf, ok := ret.Get(0).(func(string, models.UserTypeInput) map[string][]authorization.Policy); ok {
		r0 = rf(user, userTypes)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string][]authorization.Policy)
		}
	}

	if rf, ok := ret.Get(1).(func(string, models.UserTypeInput) error); ok {
		r1 = rf(user, userTypes)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUsers provides a mock function with given fields: userIds
func (_m *DbUserAndRolesGetter) GetUsers(userIds ...string) (map[string]*apikey.User, error) {
	_va := make([]interface{}, len(userIds))
	for _i := range userIds {
		_va[_i] = userIds[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for GetUsers")
	}

	var r0 map[string]*apikey.User
	var r1 error
	if rf, ok := ret.Get(0).(func(...string) (map[string]*apikey.User, error)); ok {
		return rf(userIds...)
	}
	if rf, ok := ret.Get(0).(func(...string) map[string]*apikey.User); ok {
		r0 = rf(userIds...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string]*apikey.User)
		}
	}

	if rf, ok := ret.Get(1).(func(...string) error); ok {
		r1 = rf(userIds...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RevokeRolesForUser provides a mock function with given fields: userName, roles
func (_m *DbUserAndRolesGetter) RevokeRolesForUser(userName string, roles ...string) error {
	_va := make([]interface{}, len(roles))
	for _i := range roles {
		_va[_i] = roles[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, userName)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for RevokeRolesForUser")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, ...string) error); ok {
		r0 = rf(userName, roles...)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RotateKey provides a mock function with given fields: userId, secureHash
func (_m *DbUserAndRolesGetter) RotateKey(userId string, secureHash string) error {
	ret := _m.Called(userId, secureHash)

	if len(ret) == 0 {
		panic("no return value specified for RotateKey")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string) error); ok {
		r0 = rf(userId, secureHash)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewDbUserAndRolesGetter creates a new instance of DbUserAndRolesGetter. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewDbUserAndRolesGetter(t interface {
	mock.TestingT
	Cleanup(func())
},
) *DbUserAndRolesGetter {
	mock := &DbUserAndRolesGetter{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
