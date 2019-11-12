// Code generated by go-swagger; DO NOT EDIT.

package derived

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

// NewGetTransactionSummaryParams creates a new GetTransactionSummaryParams object
// with the default values initialized.
func NewGetTransactionSummaryParams() *GetTransactionSummaryParams {
	var ()
	return &GetTransactionSummaryParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetTransactionSummaryParamsWithTimeout creates a new GetTransactionSummaryParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetTransactionSummaryParamsWithTimeout(timeout time.Duration) *GetTransactionSummaryParams {
	var ()
	return &GetTransactionSummaryParams{

		timeout: timeout,
	}
}

// NewGetTransactionSummaryParamsWithContext creates a new GetTransactionSummaryParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetTransactionSummaryParamsWithContext(ctx context.Context) *GetTransactionSummaryParams {
	var ()
	return &GetTransactionSummaryParams{

		Context: ctx,
	}
}

// NewGetTransactionSummaryParamsWithHTTPClient creates a new GetTransactionSummaryParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetTransactionSummaryParamsWithHTTPClient(client *http.Client) *GetTransactionSummaryParams {
	var ()
	return &GetTransactionSummaryParams{
		HTTPClient: client,
	}
}

/*GetTransactionSummaryParams contains all the parameters to send to the API endpoint
for the get transaction summary operation typically these are written to a http.Request
*/
type GetTransactionSummaryParams struct {

	/*AccountID
	  comma separated account Ids

	*/
	AccountID *string
	/*CategoryID
	  comma separated categoryIds

	*/
	CategoryID *string
	/*CategoryType
	  INCOME, EXPENSE, TRANSFER, UNCATEGORIZE or DEFERRED_COMPENSATION

	*/
	CategoryType *string
	/*FromDate
	  YYYY-MM-DD format

	*/
	FromDate *string
	/*GroupBy
	  CATEGORY_TYPE, HIGH_LEVEL_CATEGORY or CATEGORY

	*/
	GroupBy string
	/*Include
	  details

	*/
	Include *string
	/*IncludeUserCategory
	  TRUE/FALSE

	*/
	IncludeUserCategory *bool
	/*Interval
	  D-daily, W-weekly, M-mothly or Y-yearly

	*/
	Interval *string
	/*ToDate
	  YYYY-MM-DD format

	*/
	ToDate *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get transaction summary params
func (o *GetTransactionSummaryParams) WithTimeout(timeout time.Duration) *GetTransactionSummaryParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get transaction summary params
func (o *GetTransactionSummaryParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get transaction summary params
func (o *GetTransactionSummaryParams) WithContext(ctx context.Context) *GetTransactionSummaryParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get transaction summary params
func (o *GetTransactionSummaryParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get transaction summary params
func (o *GetTransactionSummaryParams) WithHTTPClient(client *http.Client) *GetTransactionSummaryParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get transaction summary params
func (o *GetTransactionSummaryParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAccountID adds the accountID to the get transaction summary params
func (o *GetTransactionSummaryParams) WithAccountID(accountID *string) *GetTransactionSummaryParams {
	o.SetAccountID(accountID)
	return o
}

// SetAccountID adds the accountId to the get transaction summary params
func (o *GetTransactionSummaryParams) SetAccountID(accountID *string) {
	o.AccountID = accountID
}

// WithCategoryID adds the categoryID to the get transaction summary params
func (o *GetTransactionSummaryParams) WithCategoryID(categoryID *string) *GetTransactionSummaryParams {
	o.SetCategoryID(categoryID)
	return o
}

// SetCategoryID adds the categoryId to the get transaction summary params
func (o *GetTransactionSummaryParams) SetCategoryID(categoryID *string) {
	o.CategoryID = categoryID
}

// WithCategoryType adds the categoryType to the get transaction summary params
func (o *GetTransactionSummaryParams) WithCategoryType(categoryType *string) *GetTransactionSummaryParams {
	o.SetCategoryType(categoryType)
	return o
}

// SetCategoryType adds the categoryType to the get transaction summary params
func (o *GetTransactionSummaryParams) SetCategoryType(categoryType *string) {
	o.CategoryType = categoryType
}

// WithFromDate adds the fromDate to the get transaction summary params
func (o *GetTransactionSummaryParams) WithFromDate(fromDate *string) *GetTransactionSummaryParams {
	o.SetFromDate(fromDate)
	return o
}

// SetFromDate adds the fromDate to the get transaction summary params
func (o *GetTransactionSummaryParams) SetFromDate(fromDate *string) {
	o.FromDate = fromDate
}

// WithGroupBy adds the groupBy to the get transaction summary params
func (o *GetTransactionSummaryParams) WithGroupBy(groupBy string) *GetTransactionSummaryParams {
	o.SetGroupBy(groupBy)
	return o
}

// SetGroupBy adds the groupBy to the get transaction summary params
func (o *GetTransactionSummaryParams) SetGroupBy(groupBy string) {
	o.GroupBy = groupBy
}

// WithInclude adds the include to the get transaction summary params
func (o *GetTransactionSummaryParams) WithInclude(include *string) *GetTransactionSummaryParams {
	o.SetInclude(include)
	return o
}

// SetInclude adds the include to the get transaction summary params
func (o *GetTransactionSummaryParams) SetInclude(include *string) {
	o.Include = include
}

// WithIncludeUserCategory adds the includeUserCategory to the get transaction summary params
func (o *GetTransactionSummaryParams) WithIncludeUserCategory(includeUserCategory *bool) *GetTransactionSummaryParams {
	o.SetIncludeUserCategory(includeUserCategory)
	return o
}

// SetIncludeUserCategory adds the includeUserCategory to the get transaction summary params
func (o *GetTransactionSummaryParams) SetIncludeUserCategory(includeUserCategory *bool) {
	o.IncludeUserCategory = includeUserCategory
}

// WithInterval adds the interval to the get transaction summary params
func (o *GetTransactionSummaryParams) WithInterval(interval *string) *GetTransactionSummaryParams {
	o.SetInterval(interval)
	return o
}

// SetInterval adds the interval to the get transaction summary params
func (o *GetTransactionSummaryParams) SetInterval(interval *string) {
	o.Interval = interval
}

// WithToDate adds the toDate to the get transaction summary params
func (o *GetTransactionSummaryParams) WithToDate(toDate *string) *GetTransactionSummaryParams {
	o.SetToDate(toDate)
	return o
}

// SetToDate adds the toDate to the get transaction summary params
func (o *GetTransactionSummaryParams) SetToDate(toDate *string) {
	o.ToDate = toDate
}

// WriteToRequest writes these params to a swagger request
func (o *GetTransactionSummaryParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	if o.CategoryID != nil {

		// query param categoryId
		var qrCategoryID string
		if o.CategoryID != nil {
			qrCategoryID = *o.CategoryID
		}
		qCategoryID := qrCategoryID
		if qCategoryID != "" {
			if err := r.SetQueryParam("categoryId", qCategoryID); err != nil {
				return err
			}
		}

	}

	if o.CategoryType != nil {

		// query param categoryType
		var qrCategoryType string
		if o.CategoryType != nil {
			qrCategoryType = *o.CategoryType
		}
		qCategoryType := qrCategoryType
		if qCategoryType != "" {
			if err := r.SetQueryParam("categoryType", qCategoryType); err != nil {
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

	// query param groupBy
	qrGroupBy := o.GroupBy
	qGroupBy := qrGroupBy
	if qGroupBy != "" {
		if err := r.SetQueryParam("groupBy", qGroupBy); err != nil {
			return err
		}
	}

	if o.Include != nil {

		// query param include
		var qrInclude string
		if o.Include != nil {
			qrInclude = *o.Include
		}
		qInclude := qrInclude
		if qInclude != "" {
			if err := r.SetQueryParam("include", qInclude); err != nil {
				return err
			}
		}

	}

	if o.IncludeUserCategory != nil {

		// query param includeUserCategory
		var qrIncludeUserCategory bool
		if o.IncludeUserCategory != nil {
			qrIncludeUserCategory = *o.IncludeUserCategory
		}
		qIncludeUserCategory := swag.FormatBool(qrIncludeUserCategory)
		if qIncludeUserCategory != "" {
			if err := r.SetQueryParam("includeUserCategory", qIncludeUserCategory); err != nil {
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

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}