// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
)

// GeneralResponse general response
// swagger:model generalResponse
type GeneralResponse struct {

	// error
	Error *GeneralResponseError `json:"error,omitempty"`

	// message
	Message interface{} `json:"message,omitempty"`

	// success
	Success interface{} `json:"success,omitempty"`
}

// Validate validates this general response
func (m *GeneralResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateError(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *GeneralResponse) validateError(formats strfmt.Registry) error {

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
func (m *GeneralResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GeneralResponse) UnmarshalBinary(b []byte) error {
	var res GeneralResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// GeneralResponseError general response error
// swagger:model GeneralResponseError
type GeneralResponseError struct {

	// code
	Code interface{} `json:"code,omitempty"`

	// message
	Message interface{} `json:"message,omitempty"`
}

// Validate validates this general response error
func (m *GeneralResponseError) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *GeneralResponseError) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GeneralResponseError) UnmarshalBinary(b []byte) error {
	var res GeneralResponseError
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
