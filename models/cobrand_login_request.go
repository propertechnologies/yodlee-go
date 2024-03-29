// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
)

// CobrandLoginRequest CobrandLoginRequest
// swagger:model CobrandLoginRequest
type CobrandLoginRequest struct {

	// cobrand
	Cobrand *Cobrand `json:"cobrand,omitempty"`
}

// Validate validates this cobrand login request
func (m *CobrandLoginRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCobrand(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CobrandLoginRequest) validateCobrand(formats strfmt.Registry) error {

	if swag.IsZero(m.Cobrand) { // not required
		return nil
	}

	if m.Cobrand != nil {
		if err := m.Cobrand.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cobrand")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *CobrandLoginRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CobrandLoginRequest) UnmarshalBinary(b []byte) error {
	var res CobrandLoginRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
