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

// DerivedHoldingsSummary DerivedHoldingsSummary
// swagger:model DerivedHoldingsSummary
type DerivedHoldingsSummary struct {

	// Accounts that contribute to the classification. <br><b>Required Feature Enablement</b>: Asset classification feature.<br><br><b>Applicable containers</b>: investment, insurance<br>
	// Read Only: true
	Account []*DerivedHoldingsAccount `json:"account"`

	// The classification type of the security. The supported asset classification type and the values are provided in the /holdings/assetClassificationList.<br><b>Required Feature Enablement</b>: Asset classification feature.<br><br><b>Applicable containers</b>: investment, insurance<br>
	// Read Only: true
	ClassificationType string `json:"classificationType,omitempty"`

	// The classification value that corresponds to the classification type of the holding. The supported asset classification type and the values are provided in the /holdings/assetClassificationList.<br><b>Required Feature Enablement</b>: Asset classification feature.<br><br><b>Applicable containers</b>: investment, insurance<br>
	// Read Only: true
	ClassificationValue string `json:"classificationValue,omitempty"`

	// Securities that belong to the asset classification type and contributed to the summary value.<br><b>Required Feature Enablement</b>: Asset classification feature.<br><br><b>Applicable containers</b>: investment, insurance<br>
	// Read Only: true
	Holding []*DerivedHolding `json:"holding"`

	// Summary value of the securities.<br><b>Required Feature Enablement</b>: Asset classification feature.<br><br><b>Applicable containers</b>: investment, insurance<br>
	// Read Only: true
	Value *Money `json:"value,omitempty"`
}

// Validate validates this derived holdings summary
func (m *DerivedHoldingsSummary) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateHolding(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateValue(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DerivedHoldingsSummary) validateAccount(formats strfmt.Registry) error {

	if swag.IsZero(m.Account) { // not required
		return nil
	}

	for i := 0; i < len(m.Account); i++ {
		if swag.IsZero(m.Account[i]) { // not required
			continue
		}

		if m.Account[i] != nil {
			if err := m.Account[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("account" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DerivedHoldingsSummary) validateHolding(formats strfmt.Registry) error {

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

func (m *DerivedHoldingsSummary) validateValue(formats strfmt.Registry) error {

	if swag.IsZero(m.Value) { // not required
		return nil
	}

	if m.Value != nil {
		if err := m.Value.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("value")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DerivedHoldingsSummary) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DerivedHoldingsSummary) UnmarshalBinary(b []byte) error {
	var res DerivedHoldingsSummary
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
