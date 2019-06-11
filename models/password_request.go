// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/swag"
)

// PasswordRequest password request
// swagger:model passwordRequest
type PasswordRequest struct {

	// email
	Email interface{} `json:"email,omitempty"`

	// password
	Password interface{} `json:"password,omitempty"`
}

// Validate validates this password request
func (m *PasswordRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *PasswordRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PasswordRequest) UnmarshalBinary(b []byte) error {
	var res PasswordRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}