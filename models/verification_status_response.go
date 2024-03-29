// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"strconv"

	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
)

// VerificationStatusResponse VerificationStatusResponse
// swagger:model VerificationStatusResponse
type VerificationStatusResponse struct {

	// verification
	// Read Only: true
	Verification []*Verification `json:"verification"`
}

// Validate validates this verification status response
func (m *VerificationStatusResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateVerification(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *VerificationStatusResponse) validateVerification(formats strfmt.Registry) error {

	if swag.IsZero(m.Verification) { // not required
		return nil
	}

	for i := 0; i < len(m.Verification); i++ {
		if swag.IsZero(m.Verification[i]) { // not required
			continue
		}

		if m.Verification[i] != nil {
			if err := m.Verification[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("verification" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *VerificationStatusResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *VerificationStatusResponse) UnmarshalBinary(b []byte) error {
	var res VerificationStatusResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
