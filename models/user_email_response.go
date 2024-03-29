// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
)

// UserEmailResponse user email response
// swagger:model userEmailResponse
type UserEmailResponse struct {

	// data
	Data *UserEmailResponseData `json:"data,omitempty"`

	// error
	Error *UserEmailResponseError `json:"error,omitempty"`

	// success
	Success interface{} `json:"success,omitempty"`
}

// Validate validates this user email response
func (m *UserEmailResponse) Validate(formats strfmt.Registry) error {
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

func (m *UserEmailResponse) validateData(formats strfmt.Registry) error {

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

func (m *UserEmailResponse) validateError(formats strfmt.Registry) error {

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
func (m *UserEmailResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UserEmailResponse) UnmarshalBinary(b []byte) error {
	var res UserEmailResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// UserEmailResponseData user email response data
// swagger:model UserEmailResponseData
type UserEmailResponseData struct {

	// email
	Email interface{} `json:"email,omitempty"`

	// message
	Message interface{} `json:"message,omitempty"`
}

// Validate validates this user email response data
func (m *UserEmailResponseData) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *UserEmailResponseData) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UserEmailResponseData) UnmarshalBinary(b []byte) error {
	var res UserEmailResponseData
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// UserEmailResponseError user email response error
// swagger:model UserEmailResponseError
type UserEmailResponseError struct {

	// code
	Code interface{} `json:"code,omitempty"`

	// message
	Message interface{} `json:"message,omitempty"`
}

// Validate validates this user email response error
func (m *UserEmailResponseError) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *UserEmailResponseError) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UserEmailResponseError) UnmarshalBinary(b []byte) error {
	var res UserEmailResponseError
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
