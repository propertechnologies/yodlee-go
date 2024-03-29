// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
)

// SecurityHolding SecurityHolding
// swagger:model SecurityHolding
type SecurityHolding struct {

	// id
	// Read Only: true
	ID string `json:"id,omitempty"`

	// security
	// Read Only: true
	Security *Security `json:"security,omitempty"`
}

// Validate validates this security holding
func (m *SecurityHolding) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSecurity(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SecurityHolding) validateSecurity(formats strfmt.Registry) error {

	if swag.IsZero(m.Security) { // not required
		return nil
	}

	if m.Security != nil {
		if err := m.Security.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("security")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *SecurityHolding) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SecurityHolding) UnmarshalBinary(b []byte) error {
	var res SecurityHolding
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
