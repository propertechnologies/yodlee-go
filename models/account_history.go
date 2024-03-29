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

// AccountHistory AccountHistory
// swagger:model AccountHistory
type AccountHistory struct {

	// historical balances
	// Read Only: true
	HistoricalBalances []*HistoricalBalance `json:"historicalBalances"`

	// id
	// Read Only: true
	ID int64 `json:"id,omitempty"`
}

// Validate validates this account history
func (m *AccountHistory) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateHistoricalBalances(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AccountHistory) validateHistoricalBalances(formats strfmt.Registry) error {

	if swag.IsZero(m.HistoricalBalances) { // not required
		return nil
	}

	for i := 0; i < len(m.HistoricalBalances); i++ {
		if swag.IsZero(m.HistoricalBalances[i]) { // not required
			continue
		}

		if m.HistoricalBalances[i] != nil {
			if err := m.HistoricalBalances[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("historicalBalances" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *AccountHistory) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AccountHistory) UnmarshalBinary(b []byte) error {
	var res AccountHistory
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
