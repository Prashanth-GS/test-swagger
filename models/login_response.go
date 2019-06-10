// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
)

// LoginResponse login response
// swagger:model loginResponse
type LoginResponse struct {

	// data
	Data *LoginResponseData `json:"data,omitempty"`

	// error
	Error *LoginResponseError `json:"error,omitempty"`

	// success
	Success interface{} `json:"success,omitempty"`
}

// Validate validates this login response
func (m *LoginResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateData(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateError(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *LoginResponse) validateData(formats strfmt.Registry) error {

	if swag.IsZero(m.Data) { // not required
		return nil
	}

	if m.Data != nil {
		if err := m.Data.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("data")
			}
			return err
		}
	}

	return nil
}

func (m *LoginResponse) validateError(formats strfmt.Registry) error {

	if swag.IsZero(m.Error) { // not required
		return nil
	}

	if m.Error != nil {
		if err := m.Error.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("error")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *LoginResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *LoginResponse) UnmarshalBinary(b []byte) error {
	var res LoginResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// LoginResponseData login response data
// swagger:model LoginResponseData
type LoginResponseData struct {

	// access token
	AccessToken interface{} `json:"accessToken,omitempty"`

	// expires in
	ExpiresIn interface{} `json:"expiresIn,omitempty"`
}

// Validate validates this login response data
func (m *LoginResponseData) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *LoginResponseData) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *LoginResponseData) UnmarshalBinary(b []byte) error {
	var res LoginResponseData
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// LoginResponseError login response error
// swagger:model LoginResponseError
type LoginResponseError struct {

	// code
	Code interface{} `json:"code,omitempty"`

	// message
	Message interface{} `json:"message,omitempty"`
}

// Validate validates this login response error
func (m *LoginResponseError) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *LoginResponseError) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *LoginResponseError) UnmarshalBinary(b []byte) error {
	var res LoginResponseError
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
