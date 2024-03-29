// Code generated by go-swagger; DO NOT EDIT.

package accounts

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/swag"

	strfmt "github.com/go-openapi/strfmt"
)

// NewGetHistoricalBalancesParams creates a new GetHistoricalBalancesParams object
// with the default values initialized.
func NewGetHistoricalBalancesParams() *GetHistoricalBalancesParams {
	var ()
	return &GetHistoricalBalancesParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetHistoricalBalancesParamsWithTimeout creates a new GetHistoricalBalancesParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetHistoricalBalancesParamsWithTimeout(timeout time.Duration) *GetHistoricalBalancesParams {
	var ()
	return &GetHistoricalBalancesParams{

		timeout: timeout,
	}
}

// NewGetHistoricalBalancesParamsWithContext creates a new GetHistoricalBalancesParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetHistoricalBalancesParamsWithContext(ctx context.Context) *GetHistoricalBalancesParams {
	var ()
	return &GetHistoricalBalancesParams{

		Context: ctx,
	}
}

// NewGetHistoricalBalancesParamsWithHTTPClient creates a new GetHistoricalBalancesParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetHistoricalBalancesParamsWithHTTPClient(client *http.Client) *GetHistoricalBalancesParams {
	var ()
	return &GetHistoricalBalancesParams{
		HTTPClient: client,
	}
}

/*GetHistoricalBalancesParams contains all the parameters to send to the API endpoint
for the get historical balances operation typically these are written to a http.Request
*/
type GetHistoricalBalancesParams struct {

	/*AccountID
	  accountId

	*/
	AccountID *string
	/*FromDate
	  from date for balance retrieval (YYYY-MM-DD)

	*/
	FromDate *string
	/*IncludeCF
	  Consider carry forward logic for missing balances

	*/
	IncludeCF *bool
	/*Interval
	  D-daily, W-weekly or M-monthly

	*/
	Interval *string
	/*Skip
	  skip (Min 0)

	*/
	Skip *int32
	/*ToDate
	  toDate for balance retrieval (YYYY-MM-DD)

	*/
	ToDate *string
	/*Top
	  top (Max 500)

	*/
	Top *int32

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get historical balances params
func (o *GetHistoricalBalancesParams) WithTimeout(timeout time.Duration) *GetHistoricalBalancesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get historical balances params
func (o *GetHistoricalBalancesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get historical balances params
func (o *GetHistoricalBalancesParams) WithContext(ctx context.Context) *GetHistoricalBalancesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get historical balances params
func (o *GetHistoricalBalancesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get historical balances params
func (o *GetHistoricalBalancesParams) WithHTTPClient(client *http.Client) *GetHistoricalBalancesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get historical balances params
func (o *GetHistoricalBalancesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAccountID adds the accountID to the get historical balances params
func (o *GetHistoricalBalancesParams) WithAccountID(accountID *string) *GetHistoricalBalancesParams {
	o.SetAccountID(accountID)
	return o
}

// SetAccountID adds the accountId to the get historical balances params
func (o *GetHistoricalBalancesParams) SetAccountID(accountID *string) {
	o.AccountID = accountID
}

// WithFromDate adds the fromDate to the get historical balances params
func (o *GetHistoricalBalancesParams) WithFromDate(fromDate *string) *GetHistoricalBalancesParams {
	o.SetFromDate(fromDate)
	return o
}

// SetFromDate adds the fromDate to the get historical balances params
func (o *GetHistoricalBalancesParams) SetFromDate(fromDate *string) {
	o.FromDate = fromDate
}

// WithIncludeCF adds the includeCF to the get historical balances params
func (o *GetHistoricalBalancesParams) WithIncludeCF(includeCF *bool) *GetHistoricalBalancesParams {
	o.SetIncludeCF(includeCF)
	return o
}

// SetIncludeCF adds the includeCF to the get historical balances params
func (o *GetHistoricalBalancesParams) SetIncludeCF(includeCF *bool) {
	o.IncludeCF = includeCF
}

// WithInterval adds the interval to the get historical balances params
func (o *GetHistoricalBalancesParams) WithInterval(interval *string) *GetHistoricalBalancesParams {
	o.SetInterval(interval)
	return o
}

// SetInterval adds the interval to the get historical balances params
func (o *GetHistoricalBalancesParams) SetInterval(interval *string) {
	o.Interval = interval
}

// WithSkip adds the skip to the get historical balances params
func (o *GetHistoricalBalancesParams) WithSkip(skip *int32) *GetHistoricalBalancesParams {
	o.SetSkip(skip)
	return o
}

// SetSkip adds the skip to the get historical balances params
func (o *GetHistoricalBalancesParams) SetSkip(skip *int32) {
	o.Skip = skip
}

// WithToDate adds the toDate to the get historical balances params
func (o *GetHistoricalBalancesParams) WithToDate(toDate *string) *GetHistoricalBalancesParams {
	o.SetToDate(toDate)
	return o
}

// SetToDate adds the toDate to the get historical balances params
func (o *GetHistoricalBalancesParams) SetToDate(toDate *string) {
	o.ToDate = toDate
}

// WithTop adds the top to the get historical balances params
func (o *GetHistoricalBalancesParams) WithTop(top *int32) *GetHistoricalBalancesParams {
	o.SetTop(top)
	return o
}

// SetTop adds the top to the get historical balances params
func (o *GetHistoricalBalancesParams) SetTop(top *int32) {
	o.Top = top
}

// WriteToRequest writes these params to a swagger request
func (o *GetHistoricalBalancesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.AccountID != nil {

		// query param accountId
		var qrAccountID string
		if o.AccountID != nil {
			qrAccountID = *o.AccountID
		}
		qAccountID := qrAccountID
		if qAccountID != "" {
			if err := r.SetQueryParam("accountId", qAccountID); err != nil {
				return err
			}
		}

	}

	if o.FromDate != nil {

		// query param fromDate
		var qrFromDate string
		if o.FromDate != nil {
			qrFromDate = *o.FromDate
		}
		qFromDate := qrFromDate
		if qFromDate != "" {
			if err := r.SetQueryParam("fromDate", qFromDate); err != nil {
				return err
			}
		}

	}

	if o.IncludeCF != nil {

		// query param includeCF
		var qrIncludeCF bool
		if o.IncludeCF != nil {
			qrIncludeCF = *o.IncludeCF
		}
		qIncludeCF := swag.FormatBool(qrIncludeCF)
		if qIncludeCF != "" {
			if err := r.SetQueryParam("includeCF", qIncludeCF); err != nil {
				return err
			}
		}

	}

	if o.Interval != nil {

		// query param interval
		var qrInterval string
		if o.Interval != nil {
			qrInterval = *o.Interval
		}
		qInterval := qrInterval
		if qInterval != "" {
			if err := r.SetQueryParam("interval", qInterval); err != nil {
				return err
			}
		}

	}

	if o.Skip != nil {

		// query param skip
		var qrSkip int32
		if o.Skip != nil {
			qrSkip = *o.Skip
		}
		qSkip := swag.FormatInt32(qrSkip)
		if qSkip != "" {
			if err := r.SetQueryParam("skip", qSkip); err != nil {
				return err
			}
		}

	}

	if o.ToDate != nil {

		// query param toDate
		var qrToDate string
		if o.ToDate != nil {
			qrToDate = *o.ToDate
		}
		qToDate := qrToDate
		if qToDate != "" {
			if err := r.SetQueryParam("toDate", qToDate); err != nil {
				return err
			}
		}

	}

	if o.Top != nil {

		// query param top
		var qrTop int32
		if o.Top != nil {
			qrTop = *o.Top
		}
		qTop := swag.FormatInt32(qrTop)
		if qTop != "" {
			if err := r.SetQueryParam("top", qTop); err != nil {
				return err
			}
		}

	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
