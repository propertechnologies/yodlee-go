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

// HoldingResponse HoldingResponse
// swagger:model HoldingResponse
type HoldingResponse struct {

	// holding
	// Read Only: true
	Holding []*Holding `json:"holding"`
}

// Validate validates this holding response
func (m *HoldingResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateHolding(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *HoldingResponse) validateHolding(formats strfmt.Registry) error {

	if swag.IsZero(m.Holding) { // not required
		return nil
	}

	for i := 0; i < len(m.Holding); i++ {
		if swag.IsZero(m.Holding[i]) { // not required
			continue
		}

		if m.Holding[i] != nil {
			if err := m.Holding[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("holding" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *HoldingResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *HoldingResponse) UnmarshalBinary(b []byte) error {
	var res HoldingResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
