// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
)

// CobrandLoginResponse CobrandLoginResponse
// swagger:model CobrandLoginResponse
type CobrandLoginResponse struct {

	// The application identifier.<br><br><b>Endpoints</b>:<ul><li>POST cobrand/login</li></ul>
	// Read Only: true
	ApplicationID string `json:"applicationId,omitempty"`

	// Unique identifier of the cobrand (customer) in the system.<br><br><b>Endpoints</b>:<ul><li>POST cobrand/login</li></ul>
	// Read Only: true
	CobrandID int64 `json:"cobrandId,omitempty"`

	// The customer's locale that will be considered for the localization functionality.<br><br><b>Endpoints</b>:<ul><li>POST cobrand/login</li></ul>
	// Read Only: true
	Locale string `json:"locale,omitempty"`

	// session
	Session *CobrandSession `json:"session,omitempty"`
}

// Validate validates this cobrand login response
func (m *CobrandLoginResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSession(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CobrandLoginResponse) validateSession(formats strfmt.Registry) error {

	if swag.IsZero(m.Session) { // not required
		return nil
	}

	if m.Session != nil {
		if err := m.Session.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("session")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *CobrandLoginResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CobrandLoginResponse) UnmarshalBinary(b []byte) error {
	var res CobrandLoginResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
