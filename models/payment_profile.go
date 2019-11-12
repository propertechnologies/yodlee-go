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

// PaymentProfile PaymentProfile
// swagger:model PaymentProfile
type PaymentProfile struct {

	// The address of the lender to which the monthly payments or the loan payoff amount should be paid. <br><b>Additional Details:</b>The address field applies only to the student loan account type.<br><b>Account Type</b>: Aggregated<br><b>Applicable containers</b>: loan<br><b>Endpoints</b>:<br><ul><li>GET accounts</li><li>GET accounts/{accountId}</li></ul>
	Address []*AccountAddress `json:"address"`

	// The additional information such as platform code or payment reference number that is required to make payments.<br><b>Additional Details:</b>The identifier field applies only to the student loan account type.<br><br><b>Account Type</b>: Aggregated<br><b>Applicable containers</b>: loan<br><b>Endpoints</b>:<ul><li>GET accounts</li><li>GET accounts/{accountId}</li></ul>
	Identifier *Identifier `json:"identifier,omitempty"`
}

// Validate validates this payment profile
func (m *PaymentProfile) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAddress(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIdentifier(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PaymentProfile) validateAddress(formats strfmt.Registry) error {

	if swag.IsZero(m.Address) { // not required
		return nil
	}

	for i := 0; i < len(m.Address); i++ {
		if swag.IsZero(m.Address[i]) { // not required
			continue
		}

		if m.Address[i] != nil {
			if err := m.Address[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("address" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *PaymentProfile) validateIdentifier(formats strfmt.Registry) error {

	if swag.IsZero(m.Identifier) { // not required
		return nil
	}

	if m.Identifier != nil {
		if err := m.Identifier.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("identifier")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *PaymentProfile) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PaymentProfile) UnmarshalBinary(b []byte) error {
	var res PaymentProfile
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}