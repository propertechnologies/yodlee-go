// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"

	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// HistoricalBalance HistoricalBalance
// swagger:model HistoricalBalance
type HistoricalBalance struct {

	// Date as of when the balance is last updated due to the auto account updates or user triggered updates. This balance will be carry forward for the days where there is no balance available in the system. <br><br><b>Aggregated / Manual</b>: Both <br><b>Applicable containers</b>: bank, creditCard, investment, insurance, realEstate, loan<br><b>Endpoints</b>:<ul><li>GET accounts/historicalBalances</li></ul>
	// Read Only: true
	AsOfDate string `json:"asOfDate,omitempty"`

	// Balance amount of the account.<br><br><b>Aggregated / Manual</b>: Both <br><b>Applicable containers</b>: bank, creditCard, investment, insurance, realEstate, loan<br><b>Endpoints</b>:<ul><li>GET accounts/historicalBalances</li></ul>
	// Read Only: true
	Balance *Money `json:"balance,omitempty"`

	// The source of balance information.<br><br><b>Aggregated / Manual</b>: Both <br><b>Applicable containers</b>: bank, creditCard, investment, insurance, realEstate, loan<br><b>Endpoints</b>:<ul><li>GET accounts/historicalBalances</li></ul><b>Applicable Values</b><br>
	// * S: Scraped balance from the provider site.<br>
	// * C: Calculated balance by the system.<br>
	// * CF: Last available balance that was carry forwarded for the days when account was not updated.<br>
	// Read Only: true
	// Enum: [S C CF]
	DataSourceType string `json:"dataSourceType,omitempty"`

	// Date for which the account balance was provided.  This balance could be a carryforward, calculated or a scraped balance.<br><b>Additional Details</b>:<br><b>Scraped</b>: Balance shown in the provider site. This balance gets stored in Yodlee system during system/user account updates.<br><b>CarryForward</b>: Balance carried forward from the scraped balance to the days for which the balance was not available in the system. Balance may not be available for all the days in the system due to MFA information required, error in the site, credential changes, etc.<br><b>calculated</b>: Balances that gets calculated for the days that are prior to the account added date.  <br><br><b>Aggregated / Manual</b>: Both <br><b>Applicable containers</b>: bank, creditCard, investment, insurance, realEstate, loan<br><b>Endpoints</b>:<ul><li>GET accounts/historicalBalances</li><li>GET derived/networth</li></ul>
	// Read Only: true
	Date string `json:"date,omitempty"`

	// Indicates whether the balance is an asset or liability.<br><br><b>Aggregated / Manual</b>: Both <br><b>Applicable containers</b>: bank, creditCard, investment, insurance, realEstate, loan<br><b>Endpoints</b>:<ul><li>GET accounts/historicalBalances</li></ul>
	// Read Only: true
	IsAsset *bool `json:"isAsset,omitempty"`
}

// Validate validates this historical balance
func (m *HistoricalBalance) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateBalance(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDataSourceType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *HistoricalBalance) validateBalance(formats strfmt.Registry) error {

	if swag.IsZero(m.Balance) { // not required
		return nil
	}

	if m.Balance != nil {
		if err := m.Balance.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("balance")
			}
			return err
		}
	}

	return nil
}

var historicalBalanceTypeDataSourceTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["S","C","CF"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		historicalBalanceTypeDataSourceTypePropEnum = append(historicalBalanceTypeDataSourceTypePropEnum, v)
	}
}

const (

	// HistoricalBalanceDataSourceTypeS captures enum value "S"
	HistoricalBalanceDataSourceTypeS string = "S"

	// HistoricalBalanceDataSourceTypeC captures enum value "C"
	HistoricalBalanceDataSourceTypeC string = "C"

	// HistoricalBalanceDataSourceTypeCF captures enum value "CF"
	HistoricalBalanceDataSourceTypeCF string = "CF"
)

// prop value enum
func (m *HistoricalBalance) validateDataSourceTypeEnum(path, location string, value string) error {
	if err := validate.Enum(path, location, value, historicalBalanceTypeDataSourceTypePropEnum); err != nil {
		return err
	}
	return nil
}

func (m *HistoricalBalance) validateDataSourceType(formats strfmt.Registry) error {

	if swag.IsZero(m.DataSourceType) { // not required
		return nil
	}

	// value enum
	if err := m.validateDataSourceTypeEnum("dataSourceType", "body", m.DataSourceType); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *HistoricalBalance) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *HistoricalBalance) UnmarshalBinary(b []byte) error {
	var res HistoricalBalance
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}