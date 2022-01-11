export declare namespace MyInfoComponents {
    namespace Schemas {
        /**
         * Address details (Singapore Format)
         */
        interface AddressSG {
            /**
             * Type of Address (SG or Unformatted for non SG)
             */
            type?: "SG" | "Unformatted";
            /**
             * Block of Address
             */
            block?: {
                /**
                 * example:
                 * 548
                 */
                value?: string;
            };
            /**
             * Building of Address
             */
            building?: {
                /**
                 * example:
                 *
                 */
                value?: string;
            };
            /**
             * Floor of Address
             */
            floor?: {
                /**
                 * example:
                 * 09
                 */
                value?: string;
            };
            /**
             * Unit of Address
             */
            unit?: {
                /**
                 * example:
                 * 128
                 */
                value?: string;
            };
            /**
             * Street of Address
             */
            street?: {
                /**
                 * example:
                 * BEDOK NORTH AVENUE 1
                 */
                value?: string;
            };
            /**
             * Postal Code of Address
             */
            postal?: {
                /**
                 * example:
                 * 460548
                 */
                value?: string;
            };
            /**
             * Country of Address. For AddressSG this will always be "SG".
             */
            country?: {
                code?: string;
                desc?: string;
            };
        }
        /**
         * Address details (Non-Singapore Format)
         */
        interface AddressUnformatted {
            /**
             * Type of Address (SG or Unformatted for non SG)
             */
            type?: "SG" | "Unformatted";
            /**
             * Unregistered Foreign address line 1
             */
            line1?: {
                /**
                 * example:
                 * 4578 SMITHFIELD AVENUE
                 */
                value?: string;
            };
            /**
             * Unregistered Foreign address line 2
             */
            line2?: {
                /**
                 * example:
                 * HARTFORD CT 06120
                 */
                value?: string;
            };
        }
        /**
         * Alias
         * Alias name of the Person.
         *
         * *Presentation Logic - If there is a value to `aliasname` (i.e. not empty), then `aliasname` should be displayed in a new line below `hanyupinyinname`, and prefixed with the ''@'' symbol i.e. "@`aliasname`".'*
         */
        interface Aliasname {
            /**
             * value of the field.
             * example:
             * TRICIA TAN XIAO HUI
             */
            value?: string;
        }
        /**
         * BillAdd
         * Billing Address of Person
         *
         * **Note:**
         * - address can be either a Singapore address (type: 'SG') or non Singapore address (type: 'Unformatted')
         * - check the `type` discriminator property to differentiate between the two address formats
         *
         */
        type Billadd = 
        /**
         * Address details (Singapore Format)
         * example:
         * {
         *   "classification": "C",
         *   "source": "1",
         *   "lastupdated": "2019-03-26"
         * }
         */
        /**
         * BillAdd
         * Billing Address of Person
         *
         * **Note:**
         * - address can be either a Singapore address (type: 'SG') or non Singapore address (type: 'Unformatted')
         * - check the `type` discriminator property to differentiate between the two address formats
         *
         */ DataitemAddressSg | /**
         * Address details (Non-Singapore Format)
         * example:
         * {
         *   "classification": "C",
         *   "source": "1",
         *   "lastupdated": "2019-03-26"
         * }
         */ DataitemAddressUnformatted;
        /**
         * BirthCountry
         * Country of Birth of Person.
         *
         * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
         */
        interface Birthcountry {
            /**
             *
             * example:
             * SG
             */
            code?: string;
            /**
             *
             * example:
             * SINGAPORE
             */
            desc?: string;
        }
        /**
         * example:
         * {
         *   "classification": "C",
         *   "source": "1",
         *   "lastupdated": "2019-03-26"
         * }
         */
        interface Childrenbirthrecords {
            /**
             * Data classification of data field. Default 'C' - Confidential.
             */
            classification: "C";
            /**
             * Source of data.
             *
             * * '1' - Government-verified
             * * '2' - User provided
             * * '3' - Field is Not Applicable to Person
             * * '4' - Verified by SingPass
             *
             * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
             */
            source: "1" | "2" | "3" | "4";
            /**
             * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
             */
            lastupdated: string;
            /**
             * Optional flag to indicate if data is unavalable from data source.
             *
             * **NOTE:**
             *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
             *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
             *   - If data is available from the data source, this property will not be present.
             *
             */
            unavailable: boolean;
            /**
             * Birth certificate number of child.
             */
            birthcertno?: {
                /**
                 * example:
                 * S5562882C
                 */
                value?: string;
            };
            /**
             * Full Name of child
             */
            name?: {
                /**
                 * example:
                 * Jo Tan Pei Ni
                 */
                value?: string;
            };
            /**
             * Han Yu Pin Yin name of child.
             *
             * *Presentation Logic - If there is a value to `hanyupinyinname` (i.e. not empty), then `hanyupinyinname` should be displayed in a new line below `name`, and formatted with round brackets i.e. \"(`hanyupinyinname`)\".*
             */
            hanyupinyinname?: {
                /**
                 * example:
                 * Cheng Pei Ni
                 */
                value?: string;
            };
            /**
             * Alias name of child.
             *
             * *Presentation Logic - If there is a value to `aliasname` (i.e. not empty), then `aliasname` should be displayed in a new line below `hanyupinyinname`, and prefixed with the ''@'' symbol i.e. \"@`aliasname`\".*
             */
            aliasname?: {
                /**
                 * example:
                 *
                 */
                value?: string;
            };
            /**
             * Han Yu Pin Yin Alias name of child.
             *
             * *Presentation Logic - If there is a value to `hanyupinyinaliasname` (i.e. not empty), then `hanyupinyinaliasname` should be displayed in a new line below `aliasname`, and prefixed with the ''@'' symbol i.e. \"@`hanyupinyinaliasname`\".*
             */
            hanyupinyinaliasname?: {
                /**
                 * example:
                 *
                 */
                value?: string;
            };
            /**
             * Married name of child.
             *
             * *Presentation Logic - If there is a value to `marriedname` (i.e. not empty), then `marriedname` should be displayed in a new line below `hanyupinyinaliasname`.*
             */
            marriedname?: {
                /**
                 * example:
                 *
                 */
                value?: string;
            };
            /**
             * Sex of child. Possible values:
             *
             * * 'F' - FEMALE
             * * 'M' - MALE
             * * 'U' - UNKNOWN
             */
            sex?: {
                /**
                 * example:
                 * F
                 */
                code?: "F" | "M" | "U";
                /**
                 * example:
                 * FEMALE
                 */
                desc?: "FEMALE" | "MALE" | "UNKNOWN";
            };
            /**
             * Race of child.
             *
             * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
             *
             */
            race?: {
                /**
                 * example:
                 * CN
                 */
                code?: string;
                /**
                 * example:
                 * CHINESE
                 */
                desc?: string;
            };
            /**
             * Secondary Race of child.
             *
             * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
             */
            secondaryrace?: {
                /**
                 * example:
                 *
                 */
                code?: string;
                /**
                 * example:
                 *
                 */
                desc?: string;
            };
            /**
             * Dialect of child.
             *
             * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
             */
            dialect?: {
                /**
                 * example:
                 * HK
                 */
                code?: string;
                /**
                 * example:
                 * HOKKIEN
                 */
                desc?: string;
            };
            /**
             * Life Status of child. Possible values:
             *
             * * A - ALIVE
             * * D - DECEASED
             */
            lifestatus?: {
                /**
                 * example:
                 * D
                 */
                code?: "A" | "D";
                /**
                 * example:
                 * DECEASED
                 */
                desc?: "ALIVE" | "DECEASED";
            };
            /**
             * Date of Birth of child.
             *
             * See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
             */
            dob?: {
                /**
                 * example:
                 * 2011-09-10
                 */
                value?: string;
            };
            /**
             * Time of Birth of child.
             *
             * Format: HHMM
             */
            tob?: {
                /**
                 * example:
                 * 0901
                 */
                value?: string;
            };
        }
        /**
         * CountryOfMarriage
         * Country of the latest marriage.
         *
         *
         * **Note:** This field must be made **editable** on your digital service form even though `source` is '1' (Government Verified).
         */
        interface Countryofmarriage {
            /**
             *
             * example:
             * SG
             */
            code?: string;
            /**
             *
             * example:
             * SINGAPORE
             */
            desc?: string;
        }
        /**
         * CPFBalances
         * CPF Balances of Person in SGD.
         *
         * 'ra' will not appear in the results if user does not have a Retirement Account.
         */
        interface Cpfbalances {
            /**
             * Amount Balance in CPF-MA
             */
            ma?: {
                /**
                 * example:
                 * 11470.71
                 */
                value?: number;
            };
            /**
             * Amount Balance in CPF-OA
             */
            oa?: {
                /**
                 * example:
                 * 1581.48
                 */
                value?: number;
            };
            /**
             * Amount Balance in CPF-SA
             */
            sa?: {
                /**
                 * example:
                 * 21967.09
                 */
                value?: number;
            };
            /**
             * Amount Balance in CPF-RA
             */
            ra?: {
                /**
                 * example:
                 * 0.01
                 */
                value?: number;
            };
        }
        /**
         * CPFContributions
         * Employer CPF Contributions of Person in SGD. Does not include any non-employer contributions.
         * Maximum past 14 months' of contributions.
         *
         */
        interface Cpfcontributions {
            /**
             * example:
             * [
             *   {
             *     "date": {
             *       "value": "2016-12-01"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2016-11"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2016-12-12"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2016-12"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2016-12-21"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2016-12"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-01-01"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2016-12"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-01-12"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2017-01"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-01-21"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2017-01"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-02-01"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2017-01"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-02-12"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2017-02"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-02-21"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2017-02"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-03-01"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2017-02"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-03-12"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2017-03"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-03-21"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2017-03"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-04-01"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2017-03"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-04-12"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2017-04"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-04-21"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2017-04"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-05-01"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2017-04"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-05-12"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2017-05"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-05-21"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2017-05"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-06-01"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2017-05"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-06-12"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2017-06"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-06-21"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2017-06"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-07-01"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2017-06"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-07-12"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2017-07"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-07-21"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2017-07"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-08-01"
             *     },
             *     "amount": {
             *       "value": 500
             *     },
             *     "month": {
             *       "value": "2017-07"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-08-12"
             *     },
             *     "amount": {
             *       "value": 750
             *     },
             *     "month": {
             *       "value": "2017-08"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-08-21"
             *     },
             *     "amount": {
             *       "value": 750
             *     },
             *     "month": {
             *       "value": "2017-08"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-09-01"
             *     },
             *     "amount": {
             *       "value": 750
             *     },
             *     "month": {
             *       "value": "2017-08"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-09-12"
             *     },
             *     "amount": {
             *       "value": 750
             *     },
             *     "month": {
             *       "value": "2017-09"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-09-21"
             *     },
             *     "amount": {
             *       "value": 750
             *     },
             *     "month": {
             *       "value": "2017-09"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-10-01"
             *     },
             *     "amount": {
             *       "value": 750
             *     },
             *     "month": {
             *       "value": "2017-09"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-10-12"
             *     },
             *     "amount": {
             *       "value": 750
             *     },
             *     "month": {
             *       "value": "2017-10"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-10-21"
             *     },
             *     "amount": {
             *       "value": 750
             *     },
             *     "month": {
             *       "value": "2017-10"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-11-01"
             *     },
             *     "amount": {
             *       "value": 750
             *     },
             *     "month": {
             *       "value": "2017-10"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-11-12"
             *     },
             *     "amount": {
             *       "value": 750
             *     },
             *     "month": {
             *       "value": "2017-11"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-11-21"
             *     },
             *     "amount": {
             *       "value": 750
             *     },
             *     "month": {
             *       "value": "2017-11"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-12-01"
             *     },
             *     "amount": {
             *       "value": 750
             *     },
             *     "month": {
             *       "value": "2017-11"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-12-12"
             *     },
             *     "amount": {
             *       "value": 750
             *     },
             *     "month": {
             *       "value": "2017-12"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2017-12-21"
             *     },
             *     "amount": {
             *       "value": 750
             *     },
             *     "month": {
             *       "value": "2017-12"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2018-01-01"
             *     },
             *     "amount": {
             *       "value": 750
             *     },
             *     "month": {
             *       "value": "2017-12"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2018-01-12"
             *     },
             *     "amount": {
             *       "value": 750
             *     },
             *     "month": {
             *       "value": "2018-01"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "date": {
             *       "value": "2018-01-21"
             *     },
             *     "amount": {
             *       "value": 750
             *     },
             *     "month": {
             *       "value": "2018-01"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   }
             * ]
             */
            history?: {
                /**
                 * Employer who paid the Contribution.
                 */
                employer?: {
                    /**
                     * example:
                     * Crystal Horse Invest Pte Ltd
                     */
                    value?: string;
                };
                /**
                 * Date of Contribution Paid. See "full-date" in http://xml2rfc.ietf.org/public/rfc/htm
                 */
                date?: {
                    /**
                     * example:
                     * 2017-03-01
                     */
                    value?: string;
                };
                /**
                 * Month for which CPF Contribution was paid. Format: YYYY-MM
                 */
                month?: {
                    /**
                     * example:
                     * 2017-02
                     */
                    value?: string;
                };
                /**
                 * Amount of contribution in SGD
                 */
                amount?: {
                    /**
                     * example:
                     * 500
                     */
                    value?: number;
                };
            }[];
        }
        /**
         * CPFEmployers
         * Employers who paid CPF Contributions. Maximum up to past 14 months.
         *
         */
        interface Cpfemployers {
            /**
             * example:
             * [
             *   {
             *     "month": {
             *       "value": "2016-11"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2016-12"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2016-12"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2016-12"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-01"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-01"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-01"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-02"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-02"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-02"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-03"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-03"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-03"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-04"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-04"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-04"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-05"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-05"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-05"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-06"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-06"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-06"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-07"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-07"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-07"
             *     },
             *     "employer": {
             *       "value": "Crystal Horse Invest Pte Ltd"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-08"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-08"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-08"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-09"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-09"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-09"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-10"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-10"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-10"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-11"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-11"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-11"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-12"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-12"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2017-12"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2018-01"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   },
             *   {
             *     "month": {
             *       "value": "2018-01"
             *     },
             *     "employer": {
             *       "value": "Delta Marine Consultants PL"
             *     }
             *   }
             * ]
             */
            history?: {
                /**
                 * Employer who paid the Contribution.
                 */
                employer?: {
                    /**
                     * example:
                     * Crystal Horse Invest Pte Ltd
                     */
                    value?: string;
                };
                /**
                 * Month for which CPF Contribution was paid. Format: YYYY-MM
                 */
                month?: {
                    /**
                     * example:
                     * 2017-03
                     */
                    value?: string;
                };
            }[];
        }
        /**
         * example:
         * {
         *   "classification": "C",
         *   "source": "1",
         *   "lastupdated": "2019-03-26"
         * }
         */
        interface DataFieldProperties {
            /**
             * Data classification of data field. Default 'C' - Confidential.
             */
            classification: "C";
            /**
             * Source of data.
             *
             * * '1' - Government-verified
             * * '2' - User provided
             * * '3' - Field is Not Applicable to Person
             * * '4' - Verified by SingPass
             *
             * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
             */
            source: "1" | "2" | "3" | "4";
            /**
             * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
             */
            lastupdated: string;
            /**
             * Optional flag to indicate if data is unavalable from data source.
             *
             * **NOTE:**
             *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
             *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
             *   - If data is available from the data source, this property will not be present.
             *
             */
            unavailable: boolean;
        }
        /**
         * Address details (Singapore Format)
         * example:
         * {
         *   "classification": "C",
         *   "source": "1",
         *   "lastupdated": "2019-03-26"
         * }
         */
        interface DataitemAddressSg {
            /**
             * Type of Address (SG or Unformatted for non SG)
             */
            type?: "SG" | "Unformatted";
            /**
             * Block of Address
             */
            block?: {
                /**
                 * example:
                 * 548
                 */
                value?: string;
            };
            /**
             * Building of Address
             */
            building?: {
                /**
                 * example:
                 *
                 */
                value?: string;
            };
            /**
             * Floor of Address
             */
            floor?: {
                /**
                 * example:
                 * 09
                 */
                value?: string;
            };
            /**
             * Unit of Address
             */
            unit?: {
                /**
                 * example:
                 * 128
                 */
                value?: string;
            };
            /**
             * Street of Address
             */
            street?: {
                /**
                 * example:
                 * BEDOK NORTH AVENUE 1
                 */
                value?: string;
            };
            /**
             * Postal Code of Address
             */
            postal?: {
                /**
                 * example:
                 * 460548
                 */
                value?: string;
            };
            /**
             * Country of Address. For AddressSG this will always be "SG".
             */
            country?: {
                code?: string;
                desc?: string;
            };
            /**
             * Data classification of data field. Default 'C' - Confidential.
             */
            classification: "C";
            /**
             * Source of data.
             *
             * * '1' - Government-verified
             * * '2' - User provided
             * * '3' - Field is Not Applicable to Person
             * * '4' - Verified by SingPass
             *
             * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
             */
            source: "1" | "2" | "3" | "4";
            /**
             * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
             */
            lastupdated: string;
            /**
             * Optional flag to indicate if data is unavalable from data source.
             *
             * **NOTE:**
             *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
             *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
             *   - If data is available from the data source, this property will not be present.
             *
             */
            unavailable: boolean;
        }
        /**
         * Address details (Non-Singapore Format)
         * example:
         * {
         *   "classification": "C",
         *   "source": "1",
         *   "lastupdated": "2019-03-26"
         * }
         */
        interface DataitemAddressUnformatted {
            /**
             * Type of Address (SG or Unformatted for non SG)
             */
            type?: "SG" | "Unformatted";
            /**
             * Unregistered Foreign address line 1
             */
            line1?: {
                /**
                 * example:
                 * 4578 SMITHFIELD AVENUE
                 */
                value?: string;
            };
            /**
             * Unregistered Foreign address line 2
             */
            line2?: {
                /**
                 * example:
                 * HARTFORD CT 06120
                 */
                value?: string;
            };
            /**
             * Data classification of data field. Default 'C' - Confidential.
             */
            classification: "C";
            /**
             * Source of data.
             *
             * * '1' - Government-verified
             * * '2' - User provided
             * * '3' - Field is Not Applicable to Person
             * * '4' - Verified by SingPass
             *
             * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
             */
            source: "1" | "2" | "3" | "4";
            /**
             * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
             */
            lastupdated: string;
            /**
             * Optional flag to indicate if data is unavalable from data source.
             *
             * **NOTE:**
             *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
             *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
             *   - If data is available from the data source, this property will not be present.
             *
             */
            unavailable: boolean;
        }
        /**
         * Dialect
         * Dialect of Person.
         *
         * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
         */
        interface Dialect {
            /**
             *
             * example:
             * SG
             */
            code?: string;
            /**
             *
             * example:
             * SWISS GERMAN
             */
            desc?: string;
        }
        /**
         * DivorceDate
         * Last Divorce Date of Person.
         *
         *
         * **Note:** This field must be made **editable** on your digital service form even though `source` is '1' (Government Verified).
         *
         */
        interface Divorcedate {
            /**
             * Value of data field.
             *
             * See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
             * example:
             *
             */
            value?: string;
        }
        /**
         * DOB
         * Date of Birth of Person.
         */
        interface Dob {
            /**
             * Value of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
             * example:
             * 1958-05-17
             */
            value?: string;
        }
        /**
         * Driving Licence details of Person.
         *
         */
        interface Drivinglicence {
            /**
             * Status of Certificate of Merit. Possible values:
             *
             * * Y - ELIGIBLE
             * * N - NOT ELIGIBLE
             */
            comstatus?: {
                /**
                 * example:
                 * Y
                 */
                code?: "Y" | "N";
                /**
                 *
                 * example:
                 * ELIGIBLE
                 */
                desc?: "ELIGIBLE" | "NOT ELIGIBLE";
            };
            /**
             * Total Demerit Points
             */
            totaldemeritpoints?: {
                /**
                 * example:
                 * 0
                 */
                value?: number;
            };
            /**
             *
             */
            suspension?: {
                /**
                 * Suspension Start Date
                 */
                startdate?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
                /**
                 * Suspension End Date
                 */
                enddate?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
            };
            /**
             *
             */
            disqualification?: {
                /**
                 * Disqualification Start Date
                 */
                startdate?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
                /**
                 * Disqualification End Date
                 */
                enddate?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
            };
            /**
             *
             */
            revocation?: {
                /**
                 * Revocation Start Date
                 */
                startdate?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
                /**
                 * Revocation End Date
                 */
                enddate?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
            };
            /**
             * Provisional Driving Licence (PDL)
             */
            pdl?: {
                /**
                 * Validity of PDL. Possible values:
                 *
                 * * V - VALID
                 * * E - EXPIRED
                 * * I - INVALID
                 * * N - NOT HOLDING
                 */
                validity?: {
                    /**
                     * example:
                     * V
                     */
                    code?: "V" | "E" | "I" | "N";
                    /**
                     *
                     * example:
                     * VALID
                     */
                    desc?: "VALID" | "EXPIRED" | "INVALID" | "NOT HOLDING";
                };
                /**
                 * PDL Expiry Date
                 */
                expirydate?: {
                    /**
                     * example:
                     * 2020-06-15
                     */
                    value?: string;
                };
                /**
                 * PDL Classes
                 * example:
                 * [
                 *   {
                 *     "class": {
                 *       "value": "2A"
                 *     }
                 *   },
                 *   {
                 *     "class": {
                 *       "value": "3A"
                 *     }
                 *   }
                 * ]
                 */
                classes?: {
                    class?: {
                        value?: string;
                    };
                }[];
            };
            /**
             * Qualified Driving Licence (QDL)
             */
            qdl?: {
                /**
                 * Validity of QDL. Possible values:
                 *
                 * * V - VALID
                 * * E - EXPIRED
                 * * I - INVALID
                 * * N - NOT HOLDING
                 */
                validity?: {
                    /**
                     * example:
                     * V
                     */
                    code?: "V" | "E" | "I" | "N";
                    /**
                     *
                     * example:
                     * VALID
                     */
                    desc?: "VALID" | "EXPIRED" | "INVALID" | "NOT HOLDING";
                };
                /**
                 * QDL Expiry Date
                 */
                expirydate?: {
                    /**
                     * example:
                     * 2020-06-15
                     */
                    value?: string;
                };
                /**
                 * QDL Classes. Includes Issue Date (e.g. 2B, 2018-01-01)
                 * example:
                 * [
                 *   {
                 *     "class": {
                 *       "value": "2A"
                 *     },
                 *     "issuedate": {
                 *       "value": "2018-06-06"
                 *     }
                 *   },
                 *   {
                 *     "class": {
                 *       "value": "3A"
                 *     },
                 *     "issuedate": {
                 *       "value": "2018-06-06"
                 *     }
                 *   }
                 * ]
                 */
                classes?: {
                    class?: {
                        value?: string;
                    };
                    issuedate?: {
                        value?: string;
                    };
                }[];
            };
            /**
             * Serial Number of the Photo Card
             */
            photocardserialno?: {
                /**
                 * example:
                 * 115616
                 */
                value?: string;
            };
        }
        /**
         * EduLevel
         * Highest Education Level of Person.
         *
         * * '0' - NO FORMAL QUALIFICATION / PRE-PRIMARY / LOWER PRIMARY
         * * '1' - PRIMARY
         * * '2' - LOWER SECONDARY
         * * '3' - SECONDARY
         * * '4' - POST-SECONDARY (NON-TERTIARY): GENERAL & VOCATION
         * * '5' - POLYTECHNIC DIPLOMA
         * * '6' - PROFESSIONAL QUALIFICATION AND OTHER DIPLOMA
         * * '7' - BACHELOR'S OR EQUIVALENT
         * * '8' - POSTGRADUATE DIPLOMA / CERTIFICATE (EXCLUDING MASTER'S AND DOCTORATE)
         * * '9' - MASTER'S AND DOCTORATE OR EQUIVALENT
         * * 'N' - MODULAR CERTIFICATION (NON-AWARD COURSES / NON-FULL QUALIFICATIONS)
         */
        interface Edulevel {
            /**
             *
             * example:
             * 7
             */
            code?: "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "N";
            /**
             * example:
             * BACHELOR'S OR EQUIVALENT
             */
            desc?: "NO FORMAL QUALIFICATION / PRE-PRIMARY / LOWER PRIMARY" | "PRIMARY" | "LOWER SECONDARY" | "SECONDARY" | "POST-SECONDARY (NON-TERTIARY): GENERAL & VOCATION" | "POLYTECHNIC DIPLOMA" | "PROFESSIONAL QUALIFICATION AND OTHER DIPLOMA" | "BACHELOR'S OR EQUIVALENT" | "POSTGRADUATE DIPLOMA / CERTIFICATE (EXCLUDING MASTER'S AND DOCTORATE)" | "MASTER'S AND DOCTORATE OR EQUIVALENT" | "MODULAR CERTIFICATION (NON-AWARD COURSES / NON-FULL QUALIFICATIONS)";
        }
        /**
         * Email
         * Email Address of Person.
         */
        interface Email {
            /**
             * Value of data field.
             * example:
             * test@gmail.com
             */
            value?: string;
        }
        /**
         * Employment
         * Name of Employer.
         */
        interface Employment {
            /**
             * example:
             * ALPHA
             */
            value?: string;
        }
        /**
         * EmploymentSector
         * Employment Sector of a FIN holder.
         *
         * **Note:** Only applies to a foreigner with a valid work pass.
         *
         * * Construction
         * * Manufacturing
         * * Marine Shipyard
         * * Process
         * * Services
         */
        interface Employmentsector {
            /**
             * example:
             * Manufacturing
             */
            value?: "Construction" | "Manufacturing" | "Marine Shipyard" | "Process" | "Services";
        }
        /**
         * GradYear
         * Year of Graduation of Person. Format: YYYY
         */
        interface Gradyear {
            /**
             * example:
             * 2006
             */
            value?: string;
        }
        interface Gstvoucher {
            gstregular: {
                value: number;
            };
            year: {
                value: number;
            };
            exclusion: {
                value: boolean;
            };
            gstmedisave: {
                value: number;
            };
            /**
             * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
             */
            lastupdated: string;
            gstspecial: {
                value: number;
            };
            /**
             * Source of data.
             *
             * * '1' - Government-verified
             * * '2' - User provided
             * * '3' - Field is Not Applicable to Person
             * * '4' - Verified by SingPass
             *
             * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
             */
            source: "1" | "2" | "3" | "4";
            /**
             * Data classification of data field. Default 'C' - Confidential.
             */
            classification: "C";
            signup: {
                value: boolean;
            };
        }
        /**
         * HDBOwnership
         * HDB Ownership details
         *
         * **TODO: is this tied to the registered address or the person (UINFIN) or both?**
         *
         */
        interface HDBOwnership {
            /**
             * Number of Owners. Note that this does not include executors, administrators or trustees.
             */
            noofowners?: {
                /**
                 * example:
                 * 2
                 */
                value?: number;
            };
            /**
             * Address details (Singapore Format)
             */
            address?: {
                /**
                 * Type of Address (SG or Unformatted for non SG)
                 */
                type?: "SG" | "Unformatted";
                /**
                 * Block of Address
                 */
                block?: {
                    /**
                     * example:
                     * 548
                     */
                    value?: string;
                };
                /**
                 * Building of Address
                 */
                building?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
                /**
                 * Floor of Address
                 */
                floor?: {
                    /**
                     * example:
                     * 09
                     */
                    value?: string;
                };
                /**
                 * Unit of Address
                 */
                unit?: {
                    /**
                     * example:
                     * 128
                     */
                    value?: string;
                };
                /**
                 * Street of Address
                 */
                street?: {
                    /**
                     * example:
                     * BEDOK NORTH AVENUE 1
                     */
                    value?: string;
                };
                /**
                 * Postal Code of Address
                 */
                postal?: {
                    /**
                     * example:
                     * 460548
                     */
                    value?: string;
                };
                /**
                 * Country of Address. For AddressSG this will always be "SG".
                 */
                country?: {
                    code?: string;
                    desc?: string;
                };
            };
            /**
             * HDBType
             * Flat Type of the HDB flat.
             *
             * **Note 1:** that this excludes Rental Flats, Pre-War SIT flat, PSA flat, HUDC flat, Executive Condominium and Shophouse.
             *
             * **Note 2:** If `housingtype` is available, this value will be null.
             *
             * **Note 3:** If `housingtype` &  `hdbtype` are unavailable, make this field user editable.
             *
             * * '111' - 1-ROOM FLAT (HDB)
             * * '112' - 2-ROOM FLAT (HDB)
             * * '113' - 3-ROOM FLAT (HDB)
             * * '114' - 4-ROOM FLAT (HDB)
             * * '115' - 5-ROOM FLAT (HDB)
             * * '116' - EXECUTIVE FLAT (HDB)
             * * '118' - STUDIO APARTMENT (HDB)
             */
            hdbtype?: {
                /**
                 *
                 * example:
                 * 112
                 */
                code?: "111" | "112" | "113" | "114" | "115" | "116" | "118";
                /**
                 *
                 * example:
                 * 2-ROOM FLAT (HDB)
                 */
                desc?: "1-ROOM FLAT (HDB)" | "2-ROOM FLAT (HDB)" | "3-ROOM FLAT (HDB)" | "4-ROOM FLAT (HDB)" | "5-ROOM FLAT (HDB)" | "EXECUTIVE FLAT (HDB)" | "STUDIO APARTMENT (HDB)";
            };
            /**
             * Date from which the lease period starts. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
             */
            leasecommencementdate?: {
                /**
                 * example:
                 * 2008-06-13
                 */
                value?: string;
            };
            /**
             * Term of lease (in years) for the property computed from the lease commencement date.
             */
            termoflease?: {
                /**
                 * example:
                 * 99
                 */
                value?: number;
            };
            /**
             * Effective date of flat purchase. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
             */
            dateofpurchase?: {
                /**
                 * example:
                 * 2008-06-13
                 */
                value?: string;
            };
            /**
             * Effective date of partial transfer without monetary consideration (e.g. addition, deletion or substitution of a co-owner) for an HDB sold flat.
             *
             * For partial transfer of flat where at least one of the current owner remains in the household, the Date of Purchase remains unchanged while the date of transfer of ownership will be updated.
             *
             * For outright transfer where there is a total change of all owner(s), only the Date of Purchase will be updated.
             *
             * See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14'
             */
            dateofownershiptransfer?: {
                /**
                 * example:
                 * 2018-06-13
                 */
                value?: string;
            };
            /**
             * The amount of housing loan granted to owner(s) by HDB in SGD.
             */
            loangranted?: {
                /**
                 * example:
                 * 310000.01
                 */
                value?: number;
            };
            /**
             * The number of years of loan repaymnet opted by owner(s) at the time the loan is first granted to him/her.
             */
            originalloanrepayment?: {
                /**
                 * example:
                 * 25
                 */
                value?: number;
            };
            /**
             * The remaining term of repayment for the loan in the format `years` + `months`.
             */
            balanceloanrepayment?: {
                years?: {
                    /**
                     * example:
                     * 2
                     */
                    value?: number;
                };
                months?: {
                    /**
                     * example:
                     * 6
                     */
                    value?: number;
                };
            };
            /**
             * The amount of outstanding HDB loan owed by owner(s) in SGD.
             */
            outstandingloanbalance?: {
                /**
                 * example:
                 * 50000.01
                 */
                value?: number;
            };
            /**
             * The amount of monthly instalment the owner(s) have to pay for his/her loan in SGD.
             */
            monthlyloaninstalment?: {
                /**
                 * example:
                 * 1000.01
                 */
                value?: number;
            };
        }
        /**
         * HanYuPinYinAlias
         * Han Yu Pin Yin Alias name of the Person.
         *
         * *Presentation Logic - If there is a value to `hanyupinyinaliasname` (i.e. not empty), then `hanyupinyinaliasname` should be displayed in a new line below `aliasname`, and prefixed with the ''@'' symbol i.e. "@`hanyupinyinaliasname`".*
         */
        interface Hanyupinyinaliasname {
            /**
             * example:
             * TRICIA CHEN XIAO HUI
             */
            value?: string;
        }
        /**
         * HanYuPinYin
         * Han Yu Pin Yin name of the Person.
         *
         * *Presentation Logic - If there is a value to `hanyupinyinname` (i.e. not empty), then `hanyupinyinname` should be displayed in a new line below `name`, and formatted with round brackets i.e. "(`hanyupinyinname`)"'*
         */
        interface Hanyupinyinname {
            /**
             * example:
             * CHEN XIAO HUI
             */
            value?: string;
        }
        /**
         * HDBOwnership
         * HDB Ownership details
         *
         * **TODO: is this tied to the registered address or the person (UINFIN) or both?**
         *
         */
        interface Hdbownership {
            /**
             * Number of Owners. Note that this does not include executors, administrators or trustees.
             */
            noofowners?: {
                /**
                 * example:
                 * 2
                 */
                value?: number;
            };
            /**
             * Address details (Singapore Format)
             */
            address?: {
                /**
                 * Type of Address (SG or Unformatted for non SG)
                 */
                type?: "SG" | "Unformatted";
                /**
                 * Block of Address
                 */
                block?: {
                    /**
                     * example:
                     * 548
                     */
                    value?: string;
                };
                /**
                 * Building of Address
                 */
                building?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
                /**
                 * Floor of Address
                 */
                floor?: {
                    /**
                     * example:
                     * 09
                     */
                    value?: string;
                };
                /**
                 * Unit of Address
                 */
                unit?: {
                    /**
                     * example:
                     * 128
                     */
                    value?: string;
                };
                /**
                 * Street of Address
                 */
                street?: {
                    /**
                     * example:
                     * BEDOK NORTH AVENUE 1
                     */
                    value?: string;
                };
                /**
                 * Postal Code of Address
                 */
                postal?: {
                    /**
                     * example:
                     * 460548
                     */
                    value?: string;
                };
                /**
                 * Country of Address. For AddressSG this will always be "SG".
                 */
                country?: {
                    code?: string;
                    desc?: string;
                };
            };
            /**
             * HDBType
             * Flat Type of the HDB flat.
             *
             * **Note 1:** that this excludes Rental Flats, Pre-War SIT flat, PSA flat, HUDC flat, Executive Condominium and Shophouse.
             *
             * **Note 2:** If `housingtype` is available, this value will be null.
             *
             * **Note 3:** If `housingtype` &  `hdbtype` are unavailable, make this field user editable.
             *
             * * '111' - 1-ROOM FLAT (HDB)
             * * '112' - 2-ROOM FLAT (HDB)
             * * '113' - 3-ROOM FLAT (HDB)
             * * '114' - 4-ROOM FLAT (HDB)
             * * '115' - 5-ROOM FLAT (HDB)
             * * '116' - EXECUTIVE FLAT (HDB)
             * * '118' - STUDIO APARTMENT (HDB)
             */
            hdbtype?: {
                /**
                 *
                 * example:
                 * 112
                 */
                code?: "111" | "112" | "113" | "114" | "115" | "116" | "118";
                /**
                 *
                 * example:
                 * 2-ROOM FLAT (HDB)
                 */
                desc?: "1-ROOM FLAT (HDB)" | "2-ROOM FLAT (HDB)" | "3-ROOM FLAT (HDB)" | "4-ROOM FLAT (HDB)" | "5-ROOM FLAT (HDB)" | "EXECUTIVE FLAT (HDB)" | "STUDIO APARTMENT (HDB)";
            };
            /**
             * Date from which the lease period starts. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
             */
            leasecommencementdate?: {
                /**
                 * example:
                 * 2008-06-13
                 */
                value?: string;
            };
            /**
             * Term of lease (in years) for the property computed from the lease commencement date.
             */
            termoflease?: {
                /**
                 * example:
                 * 99
                 */
                value?: number;
            };
            /**
             * Effective date of flat purchase. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
             */
            dateofpurchase?: {
                /**
                 * example:
                 * 2008-06-13
                 */
                value?: string;
            };
            /**
             * Effective date of partial transfer without monetary consideration (e.g. addition, deletion or substitution of a co-owner) for an HDB sold flat.
             *
             * For partial transfer of flat where at least one of the current owner remains in the household, the Date of Purchase remains unchanged while the date of transfer of ownership will be updated.
             *
             * For outright transfer where there is a total change of all owner(s), only the Date of Purchase will be updated.
             *
             * See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14'
             */
            dateofownershiptransfer?: {
                /**
                 * example:
                 * 2018-06-13
                 */
                value?: string;
            };
            /**
             * The amount of housing loan granted to owner(s) by HDB in SGD.
             */
            loangranted?: {
                /**
                 * example:
                 * 310000.01
                 */
                value?: number;
            };
            /**
             * The number of years of loan repaymnet opted by owner(s) at the time the loan is first granted to him/her.
             */
            originalloanrepayment?: {
                /**
                 * example:
                 * 25
                 */
                value?: number;
            };
            /**
             * The remaining term of repayment for the loan in the format `years` + `months`.
             */
            balanceloanrepayment?: {
                years?: {
                    /**
                     * example:
                     * 2
                     */
                    value?: number;
                };
                months?: {
                    /**
                     * example:
                     * 6
                     */
                    value?: number;
                };
            };
            /**
             * The amount of outstanding HDB loan owed by owner(s) in SGD.
             */
            outstandingloanbalance?: {
                /**
                 * example:
                 * 50000.01
                 */
                value?: number;
            };
            /**
             * The amount of monthly instalment the owner(s) have to pay for his/her loan in SGD.
             */
            monthlyloaninstalment?: {
                /**
                 * example:
                 * 1000.01
                 */
                value?: number;
            };
        }
        /**
         * HDBType
         * Flat Type of the HDB flat.
         *
         * **Note 1:** that this excludes Rental Flats, Pre-War SIT flat, PSA flat, HUDC flat, Executive Condominium and Shophouse.
         *
         * **Note 2:** If `housingtype` is available, this value will be null.
         *
         * **Note 3:** If `housingtype` &  `hdbtype` are unavailable, make this field user editable.
         *
         * * '111' - 1-ROOM FLAT (HDB)
         * * '112' - 2-ROOM FLAT (HDB)
         * * '113' - 3-ROOM FLAT (HDB)
         * * '114' - 4-ROOM FLAT (HDB)
         * * '115' - 5-ROOM FLAT (HDB)
         * * '116' - EXECUTIVE FLAT (HDB)
         * * '118' - STUDIO APARTMENT (HDB)
         */
        interface Hdbtype {
            /**
             *
             * example:
             * 112
             */
            code?: "111" | "112" | "113" | "114" | "115" | "116" | "118";
            /**
             *
             * example:
             * 2-ROOM FLAT (HDB)
             */
            desc?: "1-ROOM FLAT (HDB)" | "2-ROOM FLAT (HDB)" | "3-ROOM FLAT (HDB)" | "4-ROOM FLAT (HDB)" | "5-ROOM FLAT (HDB)" | "EXECUTIVE FLAT (HDB)" | "STUDIO APARTMENT (HDB)";
        }
        /**
         * HomeNo
         * Home Contact Number of Person.
         */
        interface Homeno {
            /**
             * Prefix of Phone Number. Defaults to '+'. If phone number is blank, prefix will be returned as blank.
             */
            prefix?: {
                /**
                 * example:
                 * +
                 */
                value?: string;
            };
            /**
             * Area Code of Phone Number. Default to '065'. If phone number is blank, code will be returned as blank.
             */
            areacode?: {
                /**
                 * example:
                 * 65
                 */
                value?: string;
            };
            /**
             * Phone Number.
             */
            nbr?: {
                /**
                 * example:
                 * 66132665
                 */
                value?: string;
            };
        }
        /**
         * HouseholdIncome
         * Household Income of Person in SGD.
         */
        interface Householdincome {
            /**
             * upper bound of the range of household income bracket
             */
            high?: {
                /**
                 * example:
                 * 5999
                 */
                value?: number;
            };
            /**
             * lower bound of the range of household income bracket
             */
            low?: {
                /**
                 * example:
                 * 5000
                 */
                value?: number;
            };
        }
        /**
         * HousingType
         * Housing Type of Person (non-HDB only).
         *
         * **Note 1:** If `hdbtype` is available, this value will be null.
         *
         * **Note 2:** If `housingtype` &  `hdbtype` are unavailable, make this field user editable.
         *
         * Refer to `hdbtype` for detailed HDB type.
         *
         * * '121' - DETACHED HOUSE
         * * '122' - SEMI-DETACHED HOUSE
         * * '123' - TERRACE HOUSE
         * * '131' - CONDOMINIUM
         * * '132' - EXECUTIVE CONDOMINIUM
         * * '139' - APARTMENT
         */
        interface Housingtype {
            /**
             *
             * example:
             * 123
             */
            code?: "121" | "122" | "123" | "131" | "132" | "139";
            /**
             *
             * example:
             * TERRACE HOUSE
             */
            desc?: "DETACHED HOUSE" | "SEMI-DETACHED HOUSE" | "TERRACE HOUSE" | "CONDOMINIUM" | "EXECUTIVE CONDOMINIUM" | "APARTMENT";
        }
        /**
         * MailAdd
         * Mailing Address of Person
         *
         * **Note:**
         * - address can be either a Singapore address (type: 'SG') or non Singapore address (type: 'Unformatted')
         * - check the `type` discriminator property to differentiate between the two address formats
         *
         */
        type Mailadd = 
        /**
         * Address details (Singapore Format)
         * example:
         * {
         *   "classification": "C",
         *   "source": "1",
         *   "lastupdated": "2019-03-26"
         * }
         */
        /**
         * MailAdd
         * Mailing Address of Person
         *
         * **Note:**
         * - address can be either a Singapore address (type: 'SG') or non Singapore address (type: 'Unformatted')
         * - check the `type` discriminator property to differentiate between the two address formats
         *
         */ DataitemAddressSg | /**
         * Address details (Non-Singapore Format)
         * example:
         * {
         *   "classification": "C",
         *   "source": "1",
         *   "lastupdated": "2019-03-26"
         * }
         */ DataitemAddressUnformatted;
        /**
         * Marital
         * Marital Status of Person.
         *
         * * '1' - SINGLE
         * * '2' - MARRIED
         * * '3' - WIDOWED
         * * '5' - DIVORCED
         *
         * **Note:** This field must be made **editable** on your digital service form even though `source` is '1' (Government Verified).
         */
        interface Marital {
            /**
             *
             * example:
             * 2
             */
            code?: "1" | "2" | "3" | "5";
            /**
             *
             * example:
             * MARRIED
             */
            desc?: "SINGLE" | "MARRIED" | "WIDOWED" | "DIVORCED";
        }
        /**
         * MarriageCertNo
         * Certificate number of the latest marriage.
         *
         *
         * **Note:** This field must be made **editable** on your digital service form even though `source` is '1' (Government Verified).
         */
        interface Marriagecertno {
            /**
             * Value of data field.
             * example:
             * 123456789012345
             */
            value?: string;
        }
        /**
         * MarriageDate
         * Latest Marriage Date of Person.
         *
         *
         * **Note:** This field must be made **editable** on your digital service form even though `source` is '1' (Government Verified).
         *
         */
        interface Marriagedate {
            /**
             * Value of data field.
             *
             * See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
             * example:
             * 2007-01-01
             */
            value?: string;
        }
        /**
         * MarriedName
         * Married name of the Person.
         *
         * *Presentation Logic - If there is a value to `marriedname` (i.e. not empty), then `marriedname` should be displayed in a new line below `hanyupinyinaliasname`.*
         */
        interface Marriedname {
            /**
             * value of the field, should be displayed as it is.
             * example:
             *
             */
            value?: string;
        }
        interface Merdekagen {
            eligibility: {
                value: boolean;
            };
            /**
             * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
             */
            lastupdated: string;
            quantum: {
                value: number;
            };
            /**
             * Source of data.
             *
             * * '1' - Government-verified
             * * '2' - User provided
             * * '3' - Field is Not Applicable to Person
             * * '4' - Verified by SingPass
             *
             * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
             */
            source: "1" | "2" | "3" | "4";
            /**
             * Data classification of data field. Default 'C' - Confidential.
             */
            classification: "C";
            /**
             * Message code
             * * '1' - MGP Eligibility Tag: N
             * * '2' - MGP Eligibility Tag: Y, Sign-up Tag: Y, Invalid Address Tag: N
             * * '3' - MGP Eligibility Tag: Y, Sign-up Tag: Y, Invalid Address Tag: Y
             * * '4' - MGP Eligibility Tag: Y, Sign-up Tag: N, Invalid Address Tag: N
             * * '5' - MGP Eligibility Tag: Y, Sign-up Tag: N, Invalid Address Tag: Y
             * * '6' - MGP Eligibility Tag: Y, Opt-Out Tag: Y
             * * '7' - MGP Eligibility Tag: Y, Sign-up Tag: Y, NIL Status: Y
             *
             * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
             */
            message: {
                code: "1" | "2" | "3" | "4" | "5" | "6" | "7";
                desc: "We regret that you are not eligible for the Merdeka Generation Package.  For further enquiries, please contact 1800-2222-888." | "You are eligible for the Merdeka Generation Package. For further enquiries, please contact 1800-2222-888." | "You are eligible for the Merdeka Generation Package. Please call 6391 6100 to update your NRIC address with ICA and then contact 1800-2222-888 to receive your Merdeka Generation card." | "You are eligible for the Merdeka Generation Package. Please contact 1800-2222-888 to receive your Merdeka Generation MediSave top-up." | "You are eligible for the Merdeka Generation Package. Please call 6391 6100 to update your NRIC address with ICA, and then contact 1800-2222-888 to receive your Merdeka Generation card." | "We understand that you have opted out of receiving the benefits under the Merdeka Generation Package. For further enquiries, please contact 1800-2222-888." | "Please contact 1800-2222-888 for further details on your eligibility.";
            };
        }
        /**
         * MobileNo
         * Mobile Number of Person.
         */
        interface Mobileno {
            /**
             * Prefix of Phone Number. Defaults to '+'. If phone number is blank, prefix will be returned as blank.
             */
            prefix?: {
                /**
                 * example:
                 * +
                 */
                value?: string;
            };
            /**
             * Area Code of Phone Number. Default to '065'. If phone number is blank, code will be returned as blank.
             */
            areacode?: {
                /**
                 * example:
                 * 65
                 */
                value?: string;
            };
            /**
             * Phone Number.
             */
            nbr?: {
                /**
                 * example:
                 * 66132665
                 */
                value?: string;
            };
        }
        interface NOA {
            /**
             * Assessable Income
             */
            amount?: {
                /**
                 * example:
                 * 100000.01
                 */
                value?: number;
            };
            /**
             * value of data field
             */
            yearofassessment?: {
                /**
                 * example:
                 * 2018
                 */
                value?: string;
            };
            /**
             * Assessable Income from employment
             */
            employment?: {
                /**
                 * example:
                 * 100000.01
                 */
                value?: number;
            };
            /**
             * Assessable Income from trade
             */
            trade?: {
                /**
                 * example:
                 * 0
                 */
                value?: number;
            };
            /**
             * Assessable Income from rent
             */
            rent?: {
                /**
                 * example:
                 * 0
                 */
                value?: number;
            };
            /**
             * Assessable Income from interest
             */
            interest?: {
                /**
                 * example:
                 * 0
                 */
                value?: number;
            };
            /**
             * Tax Clearance indicator. This means that tax clearance has been sought by the employer for this NOA assessment. For more information, please refer to [this](https://www.iras.gov.sg/irashome/Businesses/Employers/Tax-Clearance-for-Foreign-SPR-Employees/Getting-Tax-Clearance--A-Step-by-Step-Guide/)
             */
            taxclearance?: {
                /**
                 * example:
                 * N
                 */
                value?: "Y" | "N";
            };
            /**
             * Type of 'Notice of Assessment' (NOA)
             */
            category?: {
                /**
                 * example:
                 * ORIGINAL
                 */
                value?: "ADDITIONAL" | "AMENDED" | "ORIGINAL" | "REPAYMENT";
            };
        }
        interface NOABasic {
            /**
             * Assessable Income
             */
            amount?: {
                /**
                 * example:
                 * 100000.01
                 */
                value?: number;
            };
            /**
             * The second latest annual assessable income available from IRAS within the past 3 years.
             */
            yearofassessment?: {
                /**
                 * example:
                 * 2018
                 */
                value?: string;
            };
        }
        /**
         * Name
         * Full Name of the Person.
         */
        interface Name {
            /**
             * value of the field, should be displayed as it is.
             * example:
             * TAN XIAO HUI
             */
            value?: string;
        }
        /**
         * Nationality
         * Nationality of Person.
         *
         * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
         */
        interface Nationality {
            /**
             *
             * example:
             * SG
             */
            code?: string;
            /**
             *
             * example:
             * SINGAPORE CITIZEN
             */
            desc?: string;
        }
        /**
         * History of Notice Of Assessment
         * Detailed breakdown of latest 2 Notice of Assessments within the past three years.
         */
        interface Noahistory {
            noas?: NOA[];
        }
        /**
         * History of Notice Of Assessment (Basic)
         * Summary of latest 2 Notice of Assessments within the past three years.
         */
        interface NoahistoryBasic {
            noas?: NOABasic[];
        }
        /**
         * Occupation
         * Occupation of Person.
         */
        interface Occupation {
            /**
             * Code of occupation based on SSOC 2015.
             *
             * For full list, refer to SSOC 2015 at https://www.singstat.gov.sg/standards/standards-and-classifications/ssoc.
             *
             * For FIN holders, blank will be returned.
             *
             * **Note:** Code+Desc and Value are mutually exclusive.
             * example:
             * 53201
             */
            code?: string;
            /**
             * Description of occupation corresponding to code.
             *
             * **Note:** Code+Desc and Value are mutually exclusive.
             * example:
             * HEALTHCARE ASSISTANT
             */
            desc?: string;
            /**
             * Free text cccupation entered by user
             * **Note:** Code+Desc and Value are mutually exclusive.
             * example:
             *
             */
            value?: string;
        }
        /**
         * OwnerPrivate
         * Ownership of Private Property Status of Person (based on IRAS information).
         *
         * * true
         * * false
         * * null (data not available)
         */
        interface Ownerprivate {
            /**
             * Value of data field.
             * example:
             * false
             */
            value?: boolean;
        }
        /**
         * Partial UINFIN
         * Masked Singapore issued identification number of the Person. Only the last 3 digit and ending alphabet will be in clear.
         */
        interface Partialuinfin {
            /**
             * Value of the field, should be displayed as it is.
             * example:
             * *****111D
             */
            value?: string;
        }
        /**
         * PassExpiryDate
         * Pass expiry of a foreigner. <br/>**Note:** Only applies to a foreigner with a valid pass.
         */
        interface Passexpirydate {
            /**
             * Value of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
             * example:
             * 2022-12-31
             */
            value?: string;
        }
        /**
         * PassportExpiryDate
         * Passport Expiry Date of Person.
         */
        interface Passportexpirydate {
            /**
             * Value of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
             * example:
             * 2020-01-01
             */
            value?: string;
        }
        /**
         * PassportNumber
         * Passport Number of Person.
         */
        interface Passportnumber {
            /**
             * Value of data field.
             * example:
             * E35463874W
             */
            value?: string;
        }
        /**
         * PassStatus
         * Pass status of a FIN holder. <br/>**Note:** Only applies to a foreigner with a valid pass.
         * *	Live
         * *	Approved
         *
         */
        interface Passstatus {
            /**
             * Value of data field.
             * example:
             * Live
             */
            value?: "Live" | "Approved";
        }
        /**
         * PassType
         * Pass type of a FIN holder. <br/>**Note:** Only applies to a foreigner with a valid pass.
         *
         * * 'RPass' - Work Permit
         * * 'SPass' - S Pass
         * * 'P1Pass' - Employment Pass
         * * 'P2Pass' - Employment Pass
         * * 'QPass' - Employment Pass
         * * 'PEP' - Personalised Employment Pass
         * * 'WHP' - Work Holiday Pass
         * * 'TEP' - Training Employment Pass
         * * 'Entre' - EntrePass
         * * 'DP' - Dependent Pass
         * * 'LTVP' - Long Term Visit Pass
         * * 'LOC' - Letter of Consent
         * * 'MWP' - Miscellaneous Work Pass
         */
        interface Passtype {
            /**
             * Value of data field.
             * example:
             * RPass
             */
            code?: "RPass" | "SPass" | "P1Pass" | "P2Pass" | "QPass" | "PEP" | "WHP" | "TEP" | "Entre" | "DP" | "LTVP" | "LOC" | "MWP";
            /**
             * example:
             * Work Permit
             */
            desc?: "Work Permit" | "S Pass" | "Employment Pass" | "Employment Pass" | "Employment Pass" | "Personalised Employment Pass" | "Work Holiday Pass" | "Training Employment Pass" | "EntrePass" | "Dependent Pass" | "Long Term Visit Pass" | "Letter of Consent" | "Miscellaneous Work Pass";
        }
        /**
         * Person instance's details
         */
        interface Person {
            /**
             * UINFIN
             * Singapore issued identification number of the Person.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            uinfin?: {
                /**
                 * value of the field, should be displayed as it is.
                 * example:
                 * S1111111D
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * Name
             * Full Name of the Person.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            name?: {
                /**
                 * value of the field, should be displayed as it is.
                 * example:
                 * TAN XIAO HUI
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * HanYuPinYin
             * Han Yu Pin Yin name of the Person.
             *
             * *Presentation Logic - If there is a value to `hanyupinyinname` (i.e. not empty), then `hanyupinyinname` should be displayed in a new line below `name`, and formatted with round brackets i.e. "(`hanyupinyinname`)"'*
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            hanyupinyinname?: {
                /**
                 * example:
                 * CHEN XIAO HUI
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * Alias
             * Alias name of the Person.
             *
             * *Presentation Logic - If there is a value to `aliasname` (i.e. not empty), then `aliasname` should be displayed in a new line below `hanyupinyinname`, and prefixed with the ''@'' symbol i.e. "@`aliasname`".'*
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            aliasname?: {
                /**
                 * value of the field.
                 * example:
                 * TRICIA TAN XIAO HUI
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * HanYuPinYinAlias
             * Han Yu Pin Yin Alias name of the Person.
             *
             * *Presentation Logic - If there is a value to `hanyupinyinaliasname` (i.e. not empty), then `hanyupinyinaliasname` should be displayed in a new line below `aliasname`, and prefixed with the ''@'' symbol i.e. "@`hanyupinyinaliasname`".*
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            hanyupinyinaliasname?: {
                /**
                 * example:
                 * TRICIA CHEN XIAO HUI
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * MarriedName
             * Married name of the Person.
             *
             * *Presentation Logic - If there is a value to `marriedname` (i.e. not empty), then `marriedname` should be displayed in a new line below `hanyupinyinaliasname`.*
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            marriedname?: {
                /**
                 * value of the field, should be displayed as it is.
                 * example:
                 *
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * Sex
             * Sex of Person.
             * * 'F' - FEMALE
             * * 'M' - MALE
             * * 'U' - UNKNOWN
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            sex?: {
                /**
                 * example:
                 * F
                 */
                code?: "F" | "M" | "U";
                /**
                 *
                 * example:
                 * FEMALE
                 */
                desc?: "FEMALE" | "MALE" | "UNKNOWN";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * Race
             * Race of Person.
             *
             * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            race?: {
                /**
                 * example:
                 * CN
                 */
                code?: string;
                /**
                 * example:
                 * CHINESE
                 */
                desc?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * SecondaryRace
             * Secondary Race of Person.
             *
             * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            secondaryrace?: {
                /**
                 *
                 * example:
                 * EU
                 */
                code?: string;
                /**
                 *
                 * example:
                 * EURASIAN
                 */
                desc?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * Dialect
             * Dialect of Person.
             *
             * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            dialect?: {
                /**
                 *
                 * example:
                 * SG
                 */
                code?: string;
                /**
                 *
                 * example:
                 * SWISS GERMAN
                 */
                desc?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * Nationality
             * Nationality of Person.
             *
             * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            nationality?: {
                /**
                 *
                 * example:
                 * SG
                 */
                code?: string;
                /**
                 *
                 * example:
                 * SINGAPORE CITIZEN
                 */
                desc?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * DOB
             * Date of Birth of Person.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            dob?: {
                /**
                 * Value of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 * example:
                 * 1958-05-17
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * BirthCountry
             * Country of Birth of Person.
             *
             * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            birthcountry?: {
                /**
                 *
                 * example:
                 * SG
                 */
                code?: string;
                /**
                 *
                 * example:
                 * SINGAPORE
                 */
                desc?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * ResidentialStatus
             * Residential Status of Person. Applicable to Singapore Citizens and Permanent Residents.
             *
             *
             * **Note:** This data item is not applicable for FIN holders i.e. `source` will be '3'.
             * In such cases, the `code` and `desc` properties will be blank or empty string ("").
             *
             * * A - ALIEN
             * * C - CITIZEN
             * * P - PR
             * * U - UNKNOWN
             * * N - NOT APPLICABLE
             * * &lt; BLANK &gt; (for FIN holders only)
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            residentialstatus?: {
                /**
                 * example:
                 * C
                 */
                code?: "A" | "C" | "P" | "U" | "N" | "";
                /**
                 * example:
                 * CITIZEN
                 */
                desc?: "ALIEN" | "CITIZEN" | "PR" | "UNKNOWN" | "NOT APPLICABLE" | "";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * PassportNumber
             * Passport Number of Person.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            passportnumber?: {
                /**
                 * Value of data field.
                 * example:
                 * E35463874W
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * PassportExpiryDate
             * Passport Expiry Date of Person.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            passportexpirydate?: {
                /**
                 * Value of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 * example:
                 * 2020-01-01
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * RegAdd
             * Registered Address of Person
             *
             * **Note:**
             * - address can be either a Singapore address (type: 'SG') or non Singapore address (type: 'Unformatted')
             * - check the `type` discriminator property to differentiate between the two address formats
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            regadd?: 
            /**
             * Address details (Singapore Format)
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            /**
             * RegAdd
             * Registered Address of Person
             *
             * **Note:**
             * - address can be either a Singapore address (type: 'SG') or non Singapore address (type: 'Unformatted')
             * - check the `type` discriminator property to differentiate between the two address formats
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */ DataitemAddressSg | /**
             * Address details (Non-Singapore Format)
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */ DataitemAddressUnformatted;
            /**
             * MailAdd
             * Mailing Address of Person
             *
             * **Note:**
             * - address can be either a Singapore address (type: 'SG') or non Singapore address (type: 'Unformatted')
             * - check the `type` discriminator property to differentiate between the two address formats
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            mailadd?: 
            /**
             * Address details (Singapore Format)
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            /**
             * MailAdd
             * Mailing Address of Person
             *
             * **Note:**
             * - address can be either a Singapore address (type: 'SG') or non Singapore address (type: 'Unformatted')
             * - check the `type` discriminator property to differentiate between the two address formats
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */ DataitemAddressSg | /**
             * Address details (Non-Singapore Format)
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */ DataitemAddressUnformatted;
            /**
             * BillAdd
             * Billing Address of Person
             *
             * **Note:**
             * - address can be either a Singapore address (type: 'SG') or non Singapore address (type: 'Unformatted')
             * - check the `type` discriminator property to differentiate between the two address formats
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            billadd?: 
            /**
             * Address details (Singapore Format)
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            /**
             * BillAdd
             * Billing Address of Person
             *
             * **Note:**
             * - address can be either a Singapore address (type: 'SG') or non Singapore address (type: 'Unformatted')
             * - check the `type` discriminator property to differentiate between the two address formats
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */ DataitemAddressSg | /**
             * Address details (Non-Singapore Format)
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */ DataitemAddressUnformatted;
            /**
             * HousingType
             * Housing Type of Person (non-HDB only).
             *
             * **Note 1:** If `hdbtype` is available, this value will be null.
             *
             * **Note 2:** If `housingtype` &  `hdbtype` are unavailable, make this field user editable.
             *
             * Refer to `hdbtype` for detailed HDB type.
             *
             * * '121' - DETACHED HOUSE
             * * '122' - SEMI-DETACHED HOUSE
             * * '123' - TERRACE HOUSE
             * * '131' - CONDOMINIUM
             * * '132' - EXECUTIVE CONDOMINIUM
             * * '139' - APARTMENT
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            housingtype?: {
                /**
                 *
                 * example:
                 * 123
                 */
                code?: "121" | "122" | "123" | "131" | "132" | "139";
                /**
                 *
                 * example:
                 * TERRACE HOUSE
                 */
                desc?: "DETACHED HOUSE" | "SEMI-DETACHED HOUSE" | "TERRACE HOUSE" | "CONDOMINIUM" | "EXECUTIVE CONDOMINIUM" | "APARTMENT";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * HDBType
             * Flat Type of the HDB flat.
             *
             * **Note 1:** that this excludes Rental Flats, Pre-War SIT flat, PSA flat, HUDC flat, Executive Condominium and Shophouse.
             *
             * **Note 2:** If `housingtype` is available, this value will be null.
             *
             * **Note 3:** If `housingtype` &  `hdbtype` are unavailable, make this field user editable.
             *
             * * '111' - 1-ROOM FLAT (HDB)
             * * '112' - 2-ROOM FLAT (HDB)
             * * '113' - 3-ROOM FLAT (HDB)
             * * '114' - 4-ROOM FLAT (HDB)
             * * '115' - 5-ROOM FLAT (HDB)
             * * '116' - EXECUTIVE FLAT (HDB)
             * * '118' - STUDIO APARTMENT (HDB)
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            hdbtype?: {
                /**
                 *
                 * example:
                 * 112
                 */
                code?: "111" | "112" | "113" | "114" | "115" | "116" | "118";
                /**
                 *
                 * example:
                 * 2-ROOM FLAT (HDB)
                 */
                desc?: "1-ROOM FLAT (HDB)" | "2-ROOM FLAT (HDB)" | "3-ROOM FLAT (HDB)" | "4-ROOM FLAT (HDB)" | "5-ROOM FLAT (HDB)" | "EXECUTIVE FLAT (HDB)" | "STUDIO APARTMENT (HDB)";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * HDBOwnership
             * HDB Ownership details
             *
             */
            hdbownership?: {
                /**
                 * Number of Owners. Note that this does not include executors, administrators or trustees.
                 */
                noofowners?: {
                    /**
                     * example:
                     * 2
                     */
                    value?: number;
                };
                /**
                 * Address details (Singapore Format)
                 */
                address?: {
                    /**
                     * Type of Address (SG or Unformatted for non SG)
                     */
                    type?: "SG" | "Unformatted";
                    /**
                     * Block of Address
                     */
                    block?: {
                        /**
                         * example:
                         * 548
                         */
                        value?: string;
                    };
                    /**
                     * Building of Address
                     */
                    building?: {
                        /**
                         * example:
                         *
                         */
                        value?: string;
                    };
                    /**
                     * Floor of Address
                     */
                    floor?: {
                        /**
                         * example:
                         * 09
                         */
                        value?: string;
                    };
                    /**
                     * Unit of Address
                     */
                    unit?: {
                        /**
                         * example:
                         * 128
                         */
                        value?: string;
                    };
                    /**
                     * Street of Address
                     */
                    street?: {
                        /**
                         * example:
                         * BEDOK NORTH AVENUE 1
                         */
                        value?: string;
                    };
                    /**
                     * Postal Code of Address
                     */
                    postal?: {
                        /**
                         * example:
                         * 460548
                         */
                        value?: string;
                    };
                    /**
                     * Country of Address. For AddressSG this will always be "SG".
                     */
                    country?: {
                        code?: string;
                        desc?: string;
                    };
                };
                /**
                 * HDBType
                 * Flat Type of the HDB flat.
                 *
                 * **Note 1:** that this excludes Rental Flats, Pre-War SIT flat, PSA flat, HUDC flat, Executive Condominium and Shophouse.
                 *
                 * **Note 2:** If `housingtype` is available, this value will be null.
                 *
                 * **Note 3:** If `housingtype` &  `hdbtype` are unavailable, make this field user editable.
                 *
                 * * '111' - 1-ROOM FLAT (HDB)
                 * * '112' - 2-ROOM FLAT (HDB)
                 * * '113' - 3-ROOM FLAT (HDB)
                 * * '114' - 4-ROOM FLAT (HDB)
                 * * '115' - 5-ROOM FLAT (HDB)
                 * * '116' - EXECUTIVE FLAT (HDB)
                 * * '118' - STUDIO APARTMENT (HDB)
                 */
                hdbtype?: {
                    /**
                     *
                     * example:
                     * 112
                     */
                    code?: "111" | "112" | "113" | "114" | "115" | "116" | "118";
                    /**
                     *
                     * example:
                     * 2-ROOM FLAT (HDB)
                     */
                    desc?: "1-ROOM FLAT (HDB)" | "2-ROOM FLAT (HDB)" | "3-ROOM FLAT (HDB)" | "4-ROOM FLAT (HDB)" | "5-ROOM FLAT (HDB)" | "EXECUTIVE FLAT (HDB)" | "STUDIO APARTMENT (HDB)";
                };
                /**
                 * Date from which the lease period starts. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                leasecommencementdate?: {
                    /**
                     * example:
                     * 2008-06-13
                     */
                    value?: string;
                };
                /**
                 * Term of lease (in years) for the property computed from the lease commencement date.
                 */
                termoflease?: {
                    /**
                     * example:
                     * 99
                     */
                    value?: number;
                };
                /**
                 * Effective date of flat purchase. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                dateofpurchase?: {
                    /**
                     * example:
                     * 2008-06-13
                     */
                    value?: string;
                };
                /**
                 * Effective date of partial transfer without monetary consideration (e.g. addition, deletion or substitution of a co-owner) for an HDB sold flat.
                 *
                 * For partial transfer of flat where at least one of the current owner remains in the household, the Date of Purchase remains unchanged while the date of transfer of ownership will be updated.
                 *
                 * For outright transfer where there is a total change of all owner(s), only the Date of Purchase will be updated.
                 *
                 * See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14'
                 */
                dateofownershiptransfer?: {
                    /**
                     * example:
                     * 2018-06-13
                     */
                    value?: string;
                };
                /**
                 * The amount of housing loan granted to owner(s) by HDB in SGD.
                 */
                loangranted?: {
                    /**
                     * example:
                     * 310000.01
                     */
                    value?: number;
                };
                /**
                 * The number of years of loan repaymnet opted by owner(s) at the time the loan is first granted to him/her.
                 */
                originalloanrepayment?: {
                    /**
                     * example:
                     * 25
                     */
                    value?: number;
                };
                /**
                 * The remaining term of repayment for the loan in the format `years` + `months`.
                 */
                balanceloanrepayment?: {
                    years?: {
                        /**
                         * example:
                         * 2
                         */
                        value?: number;
                    };
                    months?: {
                        /**
                         * example:
                         * 6
                         */
                        value?: number;
                    };
                };
                /**
                 * The amount of outstanding HDB loan owed by owner(s) in SGD.
                 */
                outstandingloanbalance?: {
                    /**
                     * example:
                     * 50000.01
                     */
                    value?: number;
                };
                /**
                 * The amount of monthly instalment the owner(s) have to pay for his/her loan in SGD.
                 */
                monthlyloaninstalment?: {
                    /**
                     * example:
                     * 1000.01
                     */
                    value?: number;
                };
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            }[];
            /**
             * OwnerPrivate
             * Ownership of Private Property Status of Person (based on IRAS information).
             *
             * * true
             * * false
             * * null (data not available)
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            ownerprivate?: {
                /**
                 * Value of data field.
                 * example:
                 * false
                 */
                value?: boolean;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * Email
             * Email Address of Person.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            email?: {
                /**
                 * Value of data field.
                 * example:
                 * test@gmail.com
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * HomeNo
             * Home Contact Number of Person.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            homeno?: {
                /**
                 * Prefix of Phone Number. Defaults to '+'. If phone number is blank, prefix will be returned as blank.
                 */
                prefix?: {
                    /**
                     * example:
                     * +
                     */
                    value?: string;
                };
                /**
                 * Area Code of Phone Number. Default to '065'. If phone number is blank, code will be returned as blank.
                 */
                areacode?: {
                    /**
                     * example:
                     * 65
                     */
                    value?: string;
                };
                /**
                 * Phone Number.
                 */
                nbr?: {
                    /**
                     * example:
                     * 66132665
                     */
                    value?: string;
                };
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * MobileNo
             * Mobile Number of Person.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            mobileno?: {
                /**
                 * Prefix of Phone Number. Defaults to '+'. If phone number is blank, prefix will be returned as blank.
                 */
                prefix?: {
                    /**
                     * example:
                     * +
                     */
                    value?: string;
                };
                /**
                 * Area Code of Phone Number. Default to '065'. If phone number is blank, code will be returned as blank.
                 */
                areacode?: {
                    /**
                     * example:
                     * 65
                     */
                    value?: string;
                };
                /**
                 * Phone Number.
                 */
                nbr?: {
                    /**
                     * example:
                     * 66132665
                     */
                    value?: string;
                };
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * Marital
             * Marital Status of Person.
             *
             * * '1' - SINGLE
             * * '2' - MARRIED
             * * '3' - WIDOWED
             * * '5' - DIVORCED
             *
             * **Note:** This field must be made **editable** on your digital service form even though `source` is '1' (Government Verified).
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            marital?: {
                /**
                 *
                 * example:
                 * 2
                 */
                code?: "1" | "2" | "3" | "5";
                /**
                 *
                 * example:
                 * MARRIED
                 */
                desc?: "SINGLE" | "MARRIED" | "WIDOWED" | "DIVORCED";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * MarriageCertNo
             * Certificate number of the latest marriage.
             *
             *
             * **Note:** This field must be made **editable** on your digital service form even though `source` is '1' (Government Verified).
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            marriagecertno?: {
                /**
                 * Value of data field.
                 * example:
                 * 123456789012345
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * CountryOfMarriage
             * Country of the latest marriage.
             *
             *
             * **Note:** This field must be made **editable** on your digital service form even though `source` is '1' (Government Verified).
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            countryofmarriage?: {
                /**
                 *
                 * example:
                 * SG
                 */
                code?: string;
                /**
                 *
                 * example:
                 * SINGAPORE
                 */
                desc?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * MarriageDate
             * Latest Marriage Date of Person.
             *
             *
             * **Note:** This field must be made **editable** on your digital service form even though `source` is '1' (Government Verified).
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            marriagedate?: {
                /**
                 * Value of data field.
                 *
                 * See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 * example:
                 * 2007-01-01
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * DivorceDate
             * Last Divorce Date of Person.
             *
             *
             * **Note:** This field must be made **editable** on your digital service form even though `source` is '1' (Government Verified).
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            divorcedate?: {
                /**
                 * Value of data field.
                 *
                 * See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 * example:
                 *
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * ChildrenBirthRecords
             * This refers to only local registered birth records(based on ICA’s electronic Birth Certificate Records from 1985 onwards).
             *
             * This includes adoption of locally registered child.
             *
             * For child below 21, the child’s Birth Cert No, Name, Sex, Race, Dialect, Date of Birth and Time of Birth will be shown.
             *
             * For child above 21, only the child’s Birth Cert Number will be shown.
             */
            childrenbirthrecords?: {
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
                /**
                 * Birth certificate number of child.
                 */
                birthcertno?: {
                    /**
                     * example:
                     * S5562882C
                     */
                    value?: string;
                };
                /**
                 * Full Name of child
                 */
                name?: {
                    /**
                     * example:
                     * Jo Tan Pei Ni
                     */
                    value?: string;
                };
                /**
                 * Han Yu Pin Yin name of child.
                 *
                 * *Presentation Logic - If there is a value to `hanyupinyinname` (i.e. not empty), then `hanyupinyinname` should be displayed in a new line below `name`, and formatted with round brackets i.e. \"(`hanyupinyinname`)\".*
                 */
                hanyupinyinname?: {
                    /**
                     * example:
                     * Cheng Pei Ni
                     */
                    value?: string;
                };
                /**
                 * Alias name of child.
                 *
                 * *Presentation Logic - If there is a value to `aliasname` (i.e. not empty), then `aliasname` should be displayed in a new line below `hanyupinyinname`, and prefixed with the ''@'' symbol i.e. \"@`aliasname`\".*
                 */
                aliasname?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
                /**
                 * Han Yu Pin Yin Alias name of child.
                 *
                 * *Presentation Logic - If there is a value to `hanyupinyinaliasname` (i.e. not empty), then `hanyupinyinaliasname` should be displayed in a new line below `aliasname`, and prefixed with the ''@'' symbol i.e. \"@`hanyupinyinaliasname`\".*
                 */
                hanyupinyinaliasname?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
                /**
                 * Married name of child.
                 *
                 * *Presentation Logic - If there is a value to `marriedname` (i.e. not empty), then `marriedname` should be displayed in a new line below `hanyupinyinaliasname`.*
                 */
                marriedname?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
                /**
                 * Sex of child. Possible values:
                 *
                 * * 'F' - FEMALE
                 * * 'M' - MALE
                 * * 'U' - UNKNOWN
                 */
                sex?: {
                    /**
                     * example:
                     * F
                     */
                    code?: "F" | "M" | "U";
                    /**
                     * example:
                     * FEMALE
                     */
                    desc?: "FEMALE" | "MALE" | "UNKNOWN";
                };
                /**
                 * Race of child.
                 *
                 * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
                 *
                 */
                race?: {
                    /**
                     * example:
                     * CN
                     */
                    code?: string;
                    /**
                     * example:
                     * CHINESE
                     */
                    desc?: string;
                };
                /**
                 * Secondary Race of child.
                 *
                 * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
                 */
                secondaryrace?: {
                    /**
                     * example:
                     *
                     */
                    code?: string;
                    /**
                     * example:
                     *
                     */
                    desc?: string;
                };
                /**
                 * Dialect of child.
                 *
                 * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
                 */
                dialect?: {
                    /**
                     * example:
                     * HK
                     */
                    code?: string;
                    /**
                     * example:
                     * HOKKIEN
                     */
                    desc?: string;
                };
                /**
                 * Life Status of child. Possible values:
                 *
                 * * A - ALIVE
                 * * D - DECEASED
                 */
                lifestatus?: {
                    /**
                     * example:
                     * D
                     */
                    code?: "A" | "D";
                    /**
                     * example:
                     * DECEASED
                     */
                    desc?: "ALIVE" | "DECEASED";
                };
                /**
                 * Date of Birth of child.
                 *
                 * See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                dob?: {
                    /**
                     * example:
                     * 2011-09-10
                     */
                    value?: string;
                };
                /**
                 * Time of Birth of child.
                 *
                 * Format: HHMM
                 */
                tob?: {
                    /**
                     * example:
                     * 0901
                     */
                    value?: string;
                };
            }[];
            /**
             * SponsoredChildrenRecords
             * Details of children sponsored to be SG/PR
             *
             * For child below 21, the child’s Birth Cert No, Name, Sex, Race, Dialect, Date of Birth and Time of Birth will be shown.
             *
             * For child above 21, only the child’s last known NRIC will be shown.
             */
            sponsoredchildrenrecords?: {
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
                /**
                 * NRIC of child
                 */
                nric?: {
                    /**
                     * example:
                     * S5562882C
                     */
                    value?: string;
                };
                /**
                 * Full Name of child
                 */
                name?: {
                    /**
                     * example:
                     * Jo Tan Pei Ni
                     */
                    value?: string;
                };
                /**
                 * Han Yu Pin Yin name of child.
                 */
                hanyupinyinname?: {
                    /**
                     * example:
                     * Cheng Pei Ni
                     */
                    value?: string;
                };
                /**
                 * Alias name of child.
                 */
                aliasname?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
                /**
                 * Han Yu Pin Yin Alias name of child.
                 */
                hanyupinyinaliasname?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
                /**
                 * Married name of child.
                 */
                marriedname?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
                /**
                 * Sex of child. Possible values:
                 *
                 * * 'F' - FEMALE
                 * * 'M' - MALE
                 * * 'U' - UNKNOWN
                 */
                sex?: {
                    /**
                     * example:
                     * F
                     */
                    code?: "F" | "M" | "U";
                    /**
                     * example:
                     * FEMALE
                     */
                    desc?: "FEMALE" | "MALE" | "UNKNOWN";
                };
                /**
                 * Race of child.
                 *
                 * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
                 */
                race?: {
                    /**
                     * example:
                     * CN
                     */
                    code?: string;
                    /**
                     * example:
                     * CHINESE
                     */
                    desc?: string;
                };
                /**
                 * Secondary Race of child.
                 *
                 * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
                 */
                secondaryrace?: {
                    /**
                     * example:
                     *
                     */
                    code?: string;
                    /**
                     * example:
                     *
                     */
                    desc?: string;
                };
                /**
                 * Dialect of child.
                 *
                 * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
                 */
                dialect?: {
                    /**
                     * example:
                     * HK
                     */
                    code?: string;
                    /**
                     * example:
                     * HOKKIEN
                     */
                    desc?: string;
                };
                /**
                 * Date of Birth of child.
                 *
                 * See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                dob?: {
                    /**
                     * example:
                     * 2011-09-10
                     */
                    value?: string;
                };
                /**
                 * BirthCountry
                 * Country of Birth of child.
                 *
                 * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
                 */
                birthcountry?: {
                    /**
                     * example:
                     * SG
                     */
                    code?: string;
                    /**
                     * example:
                     * SINGAPORE
                     */
                    desc?: string;
                };
                /**
                 * Life Status of child. Possible values:
                 *
                 * * A - ALIVE
                 * * D - DECEASED
                 */
                lifestatus?: {
                    /**
                     * example:
                     * A
                     */
                    code?: "A" | "D";
                    /**
                     * example:
                     * ALIVE
                     */
                    desc?: "ALIVE" | "DECEASED";
                };
                /**
                 * ResidentialStatus
                 * Residential Status of child. Possible values:
                 *
                 * * A - ALIEN
                 * * C - CITIZEN
                 * * P - PR
                 * * U - UNKNOWN
                 * * N - NOT APPLICABLE
                 */
                residentialstatus?: {
                    /**
                     * example:
                     * C
                     */
                    code?: "A" | "C" | "P" | "U" | "N";
                    /**
                     * example:
                     * Citizen
                     */
                    desc?: "ALIEN" | "CITIZEN" | "PR" | "UNKNOWN" | "NOT APPLICABLE";
                };
                /**
                 * Nationality of child.
                 *
                 * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
                 */
                nationality?: {
                    /**
                     * example:
                     * SG
                     */
                    code?: string;
                    /**
                     * example:
                     * SINGAPORE CITIZEN
                     */
                    desc?: string;
                };
                /**
                 * Date granted Singapore Citizenship or Permanant Resident
                 *
                 * See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                scprgrantdate?: {
                    /**
                     * example:
                     * 2015-06-13
                     */
                    value?: string;
                };
            }[];
            /**
             * EduLevel
             * Highest Education Level of Person.
             *
             * * '0' - NO FORMAL QUALIFICATION / PRE-PRIMARY / LOWER PRIMARY
             * * '1' - PRIMARY
             * * '2' - LOWER SECONDARY
             * * '3' - SECONDARY
             * * '4' - POST-SECONDARY (NON-TERTIARY): GENERAL & VOCATION
             * * '5' - POLYTECHNIC DIPLOMA
             * * '6' - PROFESSIONAL QUALIFICATION AND OTHER DIPLOMA
             * * '7' - BACHELOR'S OR EQUIVALENT
             * * '8' - POSTGRADUATE DIPLOMA / CERTIFICATE (EXCLUDING MASTER'S AND DOCTORATE)
             * * '9' - MASTER'S AND DOCTORATE OR EQUIVALENT
             * * 'N' - MODULAR CERTIFICATION (NON-AWARD COURSES / NON-FULL QUALIFICATIONS)
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            edulevel?: {
                /**
                 *
                 * example:
                 * 7
                 */
                code?: "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "N";
                /**
                 * example:
                 * BACHELOR'S OR EQUIVALENT
                 */
                desc?: "NO FORMAL QUALIFICATION / PRE-PRIMARY / LOWER PRIMARY" | "PRIMARY" | "LOWER SECONDARY" | "SECONDARY" | "POST-SECONDARY (NON-TERTIARY): GENERAL & VOCATION" | "POLYTECHNIC DIPLOMA" | "PROFESSIONAL QUALIFICATION AND OTHER DIPLOMA" | "BACHELOR'S OR EQUIVALENT" | "POSTGRADUATE DIPLOMA / CERTIFICATE (EXCLUDING MASTER'S AND DOCTORATE)" | "MASTER'S AND DOCTORATE OR EQUIVALENT" | "MODULAR CERTIFICATION (NON-AWARD COURSES / NON-FULL QUALIFICATIONS)";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * GradYear
             * Year of Graduation of Person. Format: YYYY
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            gradyear?: {
                /**
                 * example:
                 * 2006
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * SchoolName
             * Name of School of Person.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            schoolname?: {
                /**
                 * Code value of school name.
                 *
                 * **Note:** Code+desc and value are mutually exclusive.
                 * example:
                 * T07GS3011J
                 */
                code?: string;
                /**
                 * Name of school represented by 'code'
                 *
                 * **Note:** Code+desc and value are mutually exclusive.
                 * example:
                 * SIGLAP SECONDARY SCHOOL
                 */
                desc?: string;
                /**
                 * Free text value of school name.
                 *
                 * **Note:** Code+desc and value are mutually exclusive.
                 * example:
                 *
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * Occupation
             * Occupation of Person.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            occupation?: {
                /**
                 * Code of occupation based on SSOC 2015.
                 *
                 * For full list, refer to SSOC 2015 at https://www.singstat.gov.sg/standards/standards-and-classifications/ssoc.
                 *
                 * For FIN holders, blank will be returned.
                 *
                 * **Note:** Code+Desc and Value are mutually exclusive.
                 * example:
                 * 53201
                 */
                code?: string;
                /**
                 * Description of occupation corresponding to code.
                 *
                 * **Note:** Code+Desc and Value are mutually exclusive.
                 * example:
                 * HEALTHCARE ASSISTANT
                 */
                desc?: string;
                /**
                 * Free text cccupation entered by user
                 * **Note:** Code+Desc and Value are mutually exclusive.
                 * example:
                 *
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * Employment
             * Name of Employer.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            employment?: {
                /**
                 * example:
                 * ALPHA
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * PassType
             * Pass type of a FIN holder. <br/>**Note:** Only applies to a foreigner with a valid pass.
             *
             * * 'RPass' - Work Permit
             * * 'SPass' - S Pass
             * * 'P1Pass' - Employment Pass
             * * 'P2Pass' - Employment Pass
             * * 'QPass' - Employment Pass
             * * 'PEP' - Personalised Employment Pass
             * * 'WHP' - Work Holiday Pass
             * * 'TEP' - Training Employment Pass
             * * 'Entre' - EntrePass
             * * 'DP' - Dependent Pass
             * * 'LTVP' - Long Term Visit Pass
             * * 'LOC' - Letter of Consent
             * * 'MWP' - Miscellaneous Work Pass
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            passtype?: {
                /**
                 * Value of data field.
                 * example:
                 * RPass
                 */
                code?: "RPass" | "SPass" | "P1Pass" | "P2Pass" | "QPass" | "PEP" | "WHP" | "TEP" | "Entre" | "DP" | "LTVP" | "LOC" | "MWP";
                /**
                 * example:
                 * Work Permit
                 */
                desc?: "Work Permit" | "S Pass" | "Employment Pass" | "Employment Pass" | "Employment Pass" | "Personalised Employment Pass" | "Work Holiday Pass" | "Training Employment Pass" | "EntrePass" | "Dependent Pass" | "Long Term Visit Pass" | "Letter of Consent" | "Miscellaneous Work Pass";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * PassStatus
             * Pass status of a FIN holder. <br/>**Note:** Only applies to a foreigner with a valid pass.
             * *	Live
             * *	Approved
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            passstatus?: {
                /**
                 * Value of data field.
                 * example:
                 * Live
                 */
                value?: "Live" | "Approved";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * PassExpiryDate
             * Pass expiry of a foreigner. <br/>**Note:** Only applies to a foreigner with a valid pass.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            passexpirydate?: {
                /**
                 * Value of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 * example:
                 * 2022-12-31
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * EmploymentSector
             * Employment Sector of a FIN holder.
             *
             * **Note:** Only applies to a foreigner with a valid work pass.
             *
             * * Construction
             * * Manufacturing
             * * Marine Shipyard
             * * Process
             * * Services
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            employmentsector?: {
                /**
                 * example:
                 * Manufacturing
                 */
                value?: "Construction" | "Manufacturing" | "Marine Shipyard" | "Process" | "Services";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * HouseholdIncome
             * Household Income of Person in SGD.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            householdincome?: {
                /**
                 * upper bound of the range of household income bracket
                 */
                high?: {
                    /**
                     * example:
                     * 5999
                     */
                    value?: number;
                };
                /**
                 * lower bound of the range of household income bracket
                 */
                low?: {
                    /**
                     * example:
                     * 5000
                     */
                    value?: number;
                };
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * **NOTE** Vehicles property is custom set to be array instead of object.
             *
             * Even though the vehicles property is defined as object in the original swagger file, the actual data is returned as array. Moreover the array will allow a person to have multiple vehicles.
             */
            vehicles?: {
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
                /**
                 * Vehicle Registration Number displayed on the vehicle number plates
                 */
                vehicleno?: {
                    /**
                     * example:
                     * SDF1235A
                     */
                    value?: string;
                };
                /**
                 * Type of Vehicles such as 'MOTOR CAR', 'STATION /WAGON/JEEP/LAND ROVER'
                 */
                type?: {
                    /**
                     * example:
                     * PASSENGER MOTOR CAR
                     */
                    value?: string;
                };
                /**
                 * In-Vehicle Unit (IU) number of the device fitted in Singapore-registered vehicles for Electronic Road Pricing (ERP) gantries and Electronic Parking System (EPS) car parks.
                 */
                iulabelno?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
                /**
                 * Vehicle Make such as 'TOYOTA', 'HONDA', 'AUDI'
                 */
                make?: {
                    /**
                     * example:
                     * TOYOTA
                     */
                    value?: string;
                };
                /**
                 * Vehicle Model such as 'COROLLA ALTIS CLASSIC 1.6 CVT', 'HRV 1.5 DX CVT'
                 */
                model?: {
                    /**
                     * example:
                     * COROLLA ALTIS
                     */
                    value?: string;
                };
                /**
                 * Vehicle Chassis Number
                 */
                chassisno?: {
                    /**
                     * example:
                     * ZC11S1735800
                     */
                    value?: string;
                };
                /**
                 * Vehicle Engine Number
                 */
                engineno?: {
                    /**
                     * example:
                     * M13A1837453
                     */
                    value?: string;
                };
                /**
                 * Vehicle Motor Number
                 */
                motorno?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
                /**
                 * Manufacturing year
                 */
                yearofmanufacture?: {
                    /**
                     * example:
                     * 2010
                     */
                    value?: string;
                };
                /**
                 * Date when vehicle is registered with LTA. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14'
                 */
                firstregistrationdate?: {
                    /**
                     * example:
                     * 2010-06-06
                     */
                    value?: string;
                };
                /**
                 * Date when vehicle is first registered in the country of origin. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14'
                 */
                originalregistrationdate?: {
                    /**
                     * example:
                     * 2010-06-06
                     */
                    value?: string;
                };
                /**
                 * Vehicle Certificate of Entitlement (COE) bid category
                 */
                coecategory?: {
                    /**
                     * example:
                     * A - CAR UP TO 1600CC & 97KW (130BHP)
                     */
                    value?: string;
                };
                /**
                 * Vehicle Certificate of Entitlement (COE) expiry date. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14'
                 */
                coeexpirydate?: {
                    /**
                     * example:
                     * 2020-06-05
                     */
                    value?: string;
                };
                /**
                 * See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14'
                 */
                roadtaxexpirydate?: {
                    /**
                     * example:
                     * 2020-06-05
                     */
                    value?: string;
                };
                /**
                 * Actual Quota Premium (QP) amount payable for the COE upon registration, conversion or COE revalidation in Singapore dollars (SGD). For renewal of COE, the value will contain actual PQP paid.
                 */
                quotapremium?: {
                    /**
                     * example:
                     * 14000.01
                     */
                    value?: number;
                };
                /**
                 * Open Market Value is the value of manufacturer invoice price, freight and insurance in Singapore dollars (SGD).
                 */
                openmarketvalue?: {
                    /**
                     * example:
                     * 25000.01
                     */
                    value?: number;
                };
                /**
                 * CO2 emission rate
                 */
                co2emission?: {
                    /**
                     * example:
                     * 146.01
                     */
                    value?: number;
                };
                /**
                 * Status of the Vehicle.
                 *
                 * * 1 - LIVE
                 * * 2 - DE-REGISTERED
                 */
                status?: {
                    /**
                     * example:
                     * 1
                     */
                    code?: "1" | "2";
                    /**
                     * example:
                     * LIVE
                     */
                    desc?: "LIVE" | "DE-REGISTERED";
                };
                /**
                 * Vehicle Primary Colour (e.g. BLACK)
                 */
                primarycolour?: {
                    /**
                     * example:
                     * BLACK
                     */
                    value?: string;
                };
                /**
                 * Vehicle Primary Colour (e.g. WHITE)
                 */
                secondarycolour?: {
                    /**
                     * example:
                     * WHITE
                     */
                    value?: string;
                };
                /**
                 * Vehicle Attachment 1 (e.g. DISABLED)
                 */
                attachment1?: {
                    /**
                     * example:
                     * DISABLED
                     */
                    value?: string;
                };
                /**
                 * Vehicle Attachment 2 (e.g. WITH SUN ROOF)
                 */
                attachment2?: {
                    /**
                     * example:
                     * WITH SUN ROOF
                     */
                    value?: string;
                };
                /**
                 * Vehicle Attachment 3 (e.g. SIDE CURTAIN)
                 */
                attachment3?: {
                    /**
                     * example:
                     * SIDE CURTAIN
                     */
                    value?: string;
                };
                /**
                 * Vehicle Scheme (e.g. REVISED OFF-PEAK CAR)
                 */
                scheme?: {
                    /**
                     * example:
                     * REVISED OFF-PEAK CAR
                     */
                    value?: string;
                };
                /**
                 * Total Hydro Carbon (THC) emission rate
                 */
                thcemission?: {
                    /**
                     * example:
                     * 1.011001
                     */
                    value?: number;
                };
                /**
                 * Carbon Monoxide emission rate
                 */
                coemission?: {
                    /**
                     * example:
                     * 1.100001
                     */
                    value?: number;
                };
                /**
                 * Nitrogen Oxide (NOx) emission rate.
                 */
                noxemission?: {
                    /**
                     * example:
                     * 0.011001
                     */
                    value?: number;
                };
                /**
                 * Particulates (PM - Atmospheric Particulate Matter) emission rate.
                 */
                pmemission?: {
                    /**
                     * example:
                     * 0.007
                     */
                    value?: number;
                };
                /**
                 * Engine Capacity in cubic centimeter (cc)
                 */
                enginecapacity?: {
                    /**
                     * example:
                     * 1600
                     */
                    value?: number;
                };
                /**
                 * Power Rate. Applicable to Electric and Hybrid vehicles powered by electric motors. Unit is Kilowatt.
                 */
                powerrate?: {
                    /**
                     * example:
                     * 1.41
                     */
                    value?: number;
                };
                /**
                 * Effective Date/Time of Ownership. See "date-time" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14'
                 */
                effectiveownership?: {
                    /**
                     * example:
                     * 2010-08-31T20:12:12+08:00
                     */
                    value?: string;
                };
                /**
                 * Propellant (e.g. Compressed Natural Gas, Diesel, Diesel-CNG, Diesel-Electric, Diesel-Electric (Plug-In), Electric, Gas, Liquefied Petroleum Gas (LPG), Petrol, Petrol-CNG, Petrol-Electric, Petrol-Electric (Plug-In), Petrol-LPG
                 */
                propellant?: {
                    /**
                     * example:
                     * Compressed Natural Gas
                     */
                    value?: string;
                };
                /**
                 * Maximum Unladen Weight in kilograms (kg)
                 */
                maximumunladenweight?: {
                    /**
                     * example:
                     * 1500
                     */
                    value?: number;
                };
                /**
                 * Maximum Laden Weight in kilograms (kg)
                 */
                maximumladenweight?: {
                    /**
                     * example:
                     * 1795
                     */
                    value?: number;
                };
                /**
                 * Minimum PARF Benefit in Singapore dollars (SGD).
                 */
                minimumparfbenefit?: {
                    /**
                     * example:
                     * 8770.01
                     */
                    value?: number;
                };
                /**
                 * Number of Transfer
                 */
                nooftransfers?: {
                    /**
                     * example:
                     * 2
                     */
                    value?: number;
                };
                /**
                 * Vehicle Parking Certificate. Applicable for Heavy Vehicles.
                 */
                vpc?: {
                    /**
                     * example:
                     * 1234567890
                     */
                    value?: string;
                };
            }[];
            /**
             * Driving Licence details of Person.
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            drivinglicence?: {
                /**
                 * Status of Certificate of Merit. Possible values:
                 *
                 * * Y - ELIGIBLE
                 * * N - NOT ELIGIBLE
                 */
                comstatus?: {
                    /**
                     * example:
                     * Y
                     */
                    code?: "Y" | "N";
                    /**
                     *
                     * example:
                     * ELIGIBLE
                     */
                    desc?: "ELIGIBLE" | "NOT ELIGIBLE";
                };
                /**
                 * Total Demerit Points
                 */
                totaldemeritpoints?: {
                    /**
                     * example:
                     * 0
                     */
                    value?: number;
                };
                /**
                 *
                 */
                suspension?: {
                    /**
                     * Suspension Start Date
                     */
                    startdate?: {
                        /**
                         * example:
                         *
                         */
                        value?: string;
                    };
                    /**
                     * Suspension End Date
                     */
                    enddate?: {
                        /**
                         * example:
                         *
                         */
                        value?: string;
                    };
                };
                /**
                 *
                 */
                disqualification?: {
                    /**
                     * Disqualification Start Date
                     */
                    startdate?: {
                        /**
                         * example:
                         *
                         */
                        value?: string;
                    };
                    /**
                     * Disqualification End Date
                     */
                    enddate?: {
                        /**
                         * example:
                         *
                         */
                        value?: string;
                    };
                };
                /**
                 *
                 */
                revocation?: {
                    /**
                     * Revocation Start Date
                     */
                    startdate?: {
                        /**
                         * example:
                         *
                         */
                        value?: string;
                    };
                    /**
                     * Revocation End Date
                     */
                    enddate?: {
                        /**
                         * example:
                         *
                         */
                        value?: string;
                    };
                };
                /**
                 * Provisional Driving Licence (PDL)
                 */
                pdl?: {
                    /**
                     * Validity of PDL. Possible values:
                     *
                     * * V - VALID
                     * * E - EXPIRED
                     * * I - INVALID
                     * * N - NOT HOLDING
                     */
                    validity?: {
                        /**
                         * example:
                         * V
                         */
                        code?: "V" | "E" | "I" | "N";
                        /**
                         *
                         * example:
                         * VALID
                         */
                        desc?: "VALID" | "EXPIRED" | "INVALID" | "NOT HOLDING";
                    };
                    /**
                     * PDL Expiry Date
                     */
                    expirydate?: {
                        /**
                         * example:
                         * 2020-06-15
                         */
                        value?: string;
                    };
                    /**
                     * PDL Classes
                     * example:
                     * [
                     *   {
                     *     "class": {
                     *       "value": "2A"
                     *     }
                     *   },
                     *   {
                     *     "class": {
                     *       "value": "3A"
                     *     }
                     *   }
                     * ]
                     */
                    classes?: {
                        class?: {
                            value?: string;
                        };
                    }[];
                };
                /**
                 * Qualified Driving Licence (QDL)
                 */
                qdl?: {
                    /**
                     * Validity of QDL. Possible values:
                     *
                     * * V - VALID
                     * * E - EXPIRED
                     * * I - INVALID
                     * * N - NOT HOLDING
                     */
                    validity?: {
                        /**
                         * example:
                         * V
                         */
                        code?: "V" | "E" | "I" | "N";
                        /**
                         *
                         * example:
                         * VALID
                         */
                        desc?: "VALID" | "EXPIRED" | "INVALID" | "NOT HOLDING";
                    };
                    /**
                     * QDL Expiry Date
                     */
                    expirydate?: {
                        /**
                         * example:
                         * 2020-06-15
                         */
                        value?: string;
                    };
                    /**
                     * QDL Classes. Includes Issue Date (e.g. 2B, 2018-01-01)
                     * example:
                     * [
                     *   {
                     *     "class": {
                     *       "value": "2A"
                     *     },
                     *     "issuedate": {
                     *       "value": "2018-06-06"
                     *     }
                     *   },
                     *   {
                     *     "class": {
                     *       "value": "3A"
                     *     },
                     *     "issuedate": {
                     *       "value": "2018-06-06"
                     *     }
                     *   }
                     * ]
                     */
                    classes?: {
                        class?: {
                            value?: string;
                        };
                        issuedate?: {
                            value?: string;
                        };
                    }[];
                };
                /**
                 * Serial Number of the Photo Card
                 */
                photocardserialno?: {
                    /**
                     * example:
                     * 115616
                     */
                    value?: string;
                };
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            gstvoucher?: {
                gstregular: {
                    value: number;
                };
                year: {
                    value: number;
                };
                exclusion: {
                    value: boolean;
                };
                gstmedisave: {
                    value: number;
                };
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                gstspecial: {
                    value: number;
                };
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                signup: {
                    value: boolean;
                };
            };
            merdekagen?: {
                eligibility: {
                    value: boolean;
                };
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                quantum: {
                    value: number;
                };
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Message code
                 * * '1' - MGP Eligibility Tag: N
                 * * '2' - MGP Eligibility Tag: Y, Sign-up Tag: Y, Invalid Address Tag: N
                 * * '3' - MGP Eligibility Tag: Y, Sign-up Tag: Y, Invalid Address Tag: Y
                 * * '4' - MGP Eligibility Tag: Y, Sign-up Tag: N, Invalid Address Tag: N
                 * * '5' - MGP Eligibility Tag: Y, Sign-up Tag: N, Invalid Address Tag: Y
                 * * '6' - MGP Eligibility Tag: Y, Opt-Out Tag: Y
                 * * '7' - MGP Eligibility Tag: Y, Sign-up Tag: Y, NIL Status: Y
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                message: {
                    code: "1" | "2" | "3" | "4" | "5" | "6" | "7";
                    desc: "We regret that you are not eligible for the Merdeka Generation Package.  For further enquiries, please contact 1800-2222-888." | "You are eligible for the Merdeka Generation Package. For further enquiries, please contact 1800-2222-888." | "You are eligible for the Merdeka Generation Package. Please call 6391 6100 to update your NRIC address with ICA and then contact 1800-2222-888 to receive your Merdeka Generation card." | "You are eligible for the Merdeka Generation Package. Please contact 1800-2222-888 to receive your Merdeka Generation MediSave top-up." | "You are eligible for the Merdeka Generation Package. Please call 6391 6100 to update your NRIC address with ICA, and then contact 1800-2222-888 to receive your Merdeka Generation card." | "We understand that you have opted out of receiving the benefits under the Merdeka Generation Package. For further enquiries, please contact 1800-2222-888." | "Please contact 1800-2222-888 for further details on your eligibility.";
                };
            };
            pioneergen?: {
                eligibility: {
                    value: boolean;
                };
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                quantum: {
                    value: string;
                };
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Message code
                 *
                 * * '1' - PG Eligibility Tag: N
                 * * '2' - PG Eligibility Tag: Y, Sign-up Tag: Y, Invalid Address Tag: N
                 * * '3' - PG Eligibility Tag: Y, Sign-up Tag: Y, Invalid Address Tag: Y
                 * * '4' - PG Eligibility Tag: Y, Sign-up Tag: N, Invalid Address Tag: N
                 * * '5' - PG Eligibility Tag: Y, Sign-up Tag: N, Invalid Address Tag: Y
                 * * '6' - PG Eligibility Tag: Y, Opt-Out Tag: Y
                 * * '7' - PG Eligibility Tag: Y, Sign-up Tag: Y, NIL Status: Y
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                message: {
                    code: "1" | "2" | "3" | "4" | "5" | "6" | "7";
                    desc: "We regret that you are not eligible for the Pioneer Generation Package.  For further enquiries, please contact 1800-2222-888." | "You are eligible for the Pioneer Generation Package. For further enquiries, please contact 1800-2222-888." | "You are eligible for the Pioneer Generation Package. Please contact 1800-2222-888 to receive your Pioneer Generation card." | "You are eligible for the Pioneer Generation Package. Please contact 1800-2222-888 to start receiving your Pioneer Generation benefits, such as your MediSave top-up." | "You are eligible for the Pioneer Generation Package. Please contact 1800-2222-888 to start receiving your Pioneer Generation benefits." | "We understand that you have opted out of receiving the benefits under the Pioneer Generation Package. For further enquiries, please contact 1800-2222-888." | "Please call 1800-2222-888 to start receiving your PG benefits.";
                };
            };
            silversupport?: {
                eligibility: {
                    value: boolean;
                };
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                amount: {
                    value: number;
                };
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                year: {
                    value: number;
                };
            };
            /**
             * Summary of latest Notice of Assessment within the past three years.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            "noa-basic"?: {
                /**
                 * Assessable Income
                 */
                amount?: {
                    /**
                     * example:
                     * 100000.01
                     */
                    value?: number;
                };
                /**
                 * The second latest annual assessable income available from IRAS within the past 3 years.
                 */
                yearofassessment?: {
                    /**
                     * example:
                     * 2018
                     */
                    value?: string;
                };
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * Detailed breakdown of latest Notice of Assessment within the past three years.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            noa?: {
                /**
                 * Assessable Income
                 */
                amount?: {
                    /**
                     * example:
                     * 100000.01
                     */
                    value?: number;
                };
                /**
                 * value of data field
                 */
                yearofassessment?: {
                    /**
                     * example:
                     * 2018
                     */
                    value?: string;
                };
                /**
                 * Assessable Income from employment
                 */
                employment?: {
                    /**
                     * example:
                     * 100000.01
                     */
                    value?: number;
                };
                /**
                 * Assessable Income from trade
                 */
                trade?: {
                    /**
                     * example:
                     * 0
                     */
                    value?: number;
                };
                /**
                 * Assessable Income from rent
                 */
                rent?: {
                    /**
                     * example:
                     * 0
                     */
                    value?: number;
                };
                /**
                 * Assessable Income from interest
                 */
                interest?: {
                    /**
                     * example:
                     * 0
                     */
                    value?: number;
                };
                /**
                 * Tax Clearance indicator. This means that tax clearance has been sought by the employer for this NOA assessment. For more information, please refer to [this](https://www.iras.gov.sg/irashome/Businesses/Employers/Tax-Clearance-for-Foreign-SPR-Employees/Getting-Tax-Clearance--A-Step-by-Step-Guide/)
                 */
                taxclearance?: {
                    /**
                     * example:
                     * N
                     */
                    value?: "Y" | "N";
                };
                /**
                 * Type of 'Notice of Assessment' (NOA)
                 */
                category?: {
                    /**
                     * example:
                     * ORIGINAL
                     */
                    value?: "ADDITIONAL" | "AMENDED" | "ORIGINAL" | "REPAYMENT";
                };
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * History of Notice Of Assessment (Basic)
             * Summary of latest 2 Notice of Assessments within the past three years.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            "noahistory-basic"?: {
                noas?: NOABasic[];
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * History of Notice Of Assessment
             * Detailed breakdown of latest 2 Notice of Assessments within the past three years.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            noahistory?: {
                noas?: NOA[];
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * CPFContributions
             * Employer CPF Contributions of Person in SGD. Does not include any non-employer contributions.
             * Maximum past 14 months' of contributions.
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            cpfcontributions?: {
                /**
                 * example:
                 * [
                 *   {
                 *     "date": {
                 *       "value": "2016-12-01"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2016-11"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2016-12-12"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2016-12"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2016-12-21"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2016-12"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-01-01"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2016-12"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-01-12"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-01"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-01-21"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-01"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-02-01"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-01"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-02-12"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-02"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-02-21"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-02"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-03-01"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-02"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-03-12"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-03"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-03-21"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-03"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-04-01"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-03"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-04-12"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-04"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-04-21"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-04"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-05-01"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-04"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-05-12"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-05"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-05-21"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-05"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-06-01"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-05"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-06-12"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-06"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-06-21"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-06"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-07-01"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-06"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-07-12"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-07"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-07-21"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-07"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-08-01"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-07"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-08-12"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-08"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-08-21"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-08"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-09-01"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-08"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-09-12"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-09"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-09-21"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-09"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-10-01"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-09"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-10-12"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-10"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-10-21"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-10"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-11-01"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-10"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-11-12"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-11"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-11-21"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-11"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-12-01"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-11"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-12-12"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-12"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-12-21"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-12"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2018-01-01"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-12"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2018-01-12"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2018-01"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2018-01-21"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2018-01"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   }
                 * ]
                 */
                history?: {
                    /**
                     * Employer who paid the Contribution.
                     */
                    employer?: {
                        /**
                         * example:
                         * Crystal Horse Invest Pte Ltd
                         */
                        value?: string;
                    };
                    /**
                     * Date of Contribution Paid. See "full-date" in http://xml2rfc.ietf.org/public/rfc/htm
                     */
                    date?: {
                        /**
                         * example:
                         * 2017-03-01
                         */
                        value?: string;
                    };
                    /**
                     * Month for which CPF Contribution was paid. Format: YYYY-MM
                     */
                    month?: {
                        /**
                         * example:
                         * 2017-02
                         */
                        value?: string;
                    };
                    /**
                     * Amount of contribution in SGD
                     */
                    amount?: {
                        /**
                         * example:
                         * 500
                         */
                        value?: number;
                    };
                }[];
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * CPFEmployers
             * Employers who paid CPF Contributions. Maximum up to past 14 months.
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            cpfemployers?: {
                /**
                 * example:
                 * [
                 *   {
                 *     "month": {
                 *       "value": "2016-11"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2016-12"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2016-12"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2016-12"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-01"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-01"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-01"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-02"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-02"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-02"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-03"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-03"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-03"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-04"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-04"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-04"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-05"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-05"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-05"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-06"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-06"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-06"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-07"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-07"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-07"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-08"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-08"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-08"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-09"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-09"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-09"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-10"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-10"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-10"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-11"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-11"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-11"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-12"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-12"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-12"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2018-01"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2018-01"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   }
                 * ]
                 */
                history?: {
                    /**
                     * Employer who paid the Contribution.
                     */
                    employer?: {
                        /**
                         * example:
                         * Crystal Horse Invest Pte Ltd
                         */
                        value?: string;
                    };
                    /**
                     * Month for which CPF Contribution was paid. Format: YYYY-MM
                     */
                    month?: {
                        /**
                         * example:
                         * 2017-03
                         */
                        value?: string;
                    };
                }[];
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * CPFBalances
             * CPF Balances of Person in SGD.
             *
             * 'ra' will not appear in the results if user does not have a Retirement Account.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            cpfbalances?: {
                /**
                 * Amount Balance in CPF-MA
                 */
                ma?: {
                    /**
                     * example:
                     * 11470.71
                     */
                    value?: number;
                };
                /**
                 * Amount Balance in CPF-OA
                 */
                oa?: {
                    /**
                     * example:
                     * 1581.48
                     */
                    value?: number;
                };
                /**
                 * Amount Balance in CPF-SA
                 */
                sa?: {
                    /**
                     * example:
                     * 21967.09
                     */
                    value?: number;
                };
                /**
                 * Amount Balance in CPF-RA
                 */
                ra?: {
                    /**
                     * example:
                     * 0.01
                     */
                    value?: number;
                };
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
        }
        /**
         * Person instance's details
         */
        interface PersonCommon {
            /**
             * UINFIN
             * Singapore issued identification number of the Person.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            uinfin?: {
                /**
                 * value of the field, should be displayed as it is.
                 * example:
                 * S1111111D
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * Name
             * Full Name of the Person.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            name?: {
                /**
                 * value of the field, should be displayed as it is.
                 * example:
                 * TAN XIAO HUI
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * HanYuPinYin
             * Han Yu Pin Yin name of the Person.
             *
             * *Presentation Logic - If there is a value to `hanyupinyinname` (i.e. not empty), then `hanyupinyinname` should be displayed in a new line below `name`, and formatted with round brackets i.e. "(`hanyupinyinname`)"'*
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            hanyupinyinname?: {
                /**
                 * example:
                 * CHEN XIAO HUI
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * Alias
             * Alias name of the Person.
             *
             * *Presentation Logic - If there is a value to `aliasname` (i.e. not empty), then `aliasname` should be displayed in a new line below `hanyupinyinname`, and prefixed with the ''@'' symbol i.e. "@`aliasname`".'*
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            aliasname?: {
                /**
                 * value of the field.
                 * example:
                 * TRICIA TAN XIAO HUI
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * HanYuPinYinAlias
             * Han Yu Pin Yin Alias name of the Person.
             *
             * *Presentation Logic - If there is a value to `hanyupinyinaliasname` (i.e. not empty), then `hanyupinyinaliasname` should be displayed in a new line below `aliasname`, and prefixed with the ''@'' symbol i.e. "@`hanyupinyinaliasname`".*
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            hanyupinyinaliasname?: {
                /**
                 * example:
                 * TRICIA CHEN XIAO HUI
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * MarriedName
             * Married name of the Person.
             *
             * *Presentation Logic - If there is a value to `marriedname` (i.e. not empty), then `marriedname` should be displayed in a new line below `hanyupinyinaliasname`.*
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            marriedname?: {
                /**
                 * value of the field, should be displayed as it is.
                 * example:
                 *
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * Sex
             * Sex of Person.
             * * 'F' - FEMALE
             * * 'M' - MALE
             * * 'U' - UNKNOWN
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            sex?: {
                /**
                 * example:
                 * F
                 */
                code?: "F" | "M" | "U";
                /**
                 *
                 * example:
                 * FEMALE
                 */
                desc?: "FEMALE" | "MALE" | "UNKNOWN";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * Race
             * Race of Person.
             *
             * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            race?: {
                /**
                 * example:
                 * CN
                 */
                code?: string;
                /**
                 * example:
                 * CHINESE
                 */
                desc?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * SecondaryRace
             * Secondary Race of Person.
             *
             * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            secondaryrace?: {
                /**
                 *
                 * example:
                 * EU
                 */
                code?: string;
                /**
                 *
                 * example:
                 * EURASIAN
                 */
                desc?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * Dialect
             * Dialect of Person.
             *
             * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            dialect?: {
                /**
                 *
                 * example:
                 * SG
                 */
                code?: string;
                /**
                 *
                 * example:
                 * SWISS GERMAN
                 */
                desc?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * Nationality
             * Nationality of Person.
             *
             * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            nationality?: {
                /**
                 *
                 * example:
                 * SG
                 */
                code?: string;
                /**
                 *
                 * example:
                 * SINGAPORE CITIZEN
                 */
                desc?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * DOB
             * Date of Birth of Person.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            dob?: {
                /**
                 * Value of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 * example:
                 * 1958-05-17
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * BirthCountry
             * Country of Birth of Person.
             *
             * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            birthcountry?: {
                /**
                 *
                 * example:
                 * SG
                 */
                code?: string;
                /**
                 *
                 * example:
                 * SINGAPORE
                 */
                desc?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * ResidentialStatus
             * Residential Status of Person. Applicable to Singapore Citizens and Permanent Residents.
             *
             *
             * **Note:** This data item is not applicable for FIN holders i.e. `source` will be '3'.
             * In such cases, the `code` and `desc` properties will be blank or empty string ("").
             *
             * * A - ALIEN
             * * C - CITIZEN
             * * P - PR
             * * U - UNKNOWN
             * * N - NOT APPLICABLE
             * * &lt; BLANK &gt; (for FIN holders only)
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            residentialstatus?: {
                /**
                 * example:
                 * C
                 */
                code?: "A" | "C" | "P" | "U" | "N" | "";
                /**
                 * example:
                 * CITIZEN
                 */
                desc?: "ALIEN" | "CITIZEN" | "PR" | "UNKNOWN" | "NOT APPLICABLE" | "";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * PassportNumber
             * Passport Number of Person.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            passportnumber?: {
                /**
                 * Value of data field.
                 * example:
                 * E35463874W
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * PassportExpiryDate
             * Passport Expiry Date of Person.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            passportexpirydate?: {
                /**
                 * Value of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 * example:
                 * 2020-01-01
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * RegAdd
             * Registered Address of Person
             *
             * **Note:**
             * - address can be either a Singapore address (type: 'SG') or non Singapore address (type: 'Unformatted')
             * - check the `type` discriminator property to differentiate between the two address formats
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            regadd?: 
            /**
             * Address details (Singapore Format)
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            /**
             * RegAdd
             * Registered Address of Person
             *
             * **Note:**
             * - address can be either a Singapore address (type: 'SG') or non Singapore address (type: 'Unformatted')
             * - check the `type` discriminator property to differentiate between the two address formats
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */ DataitemAddressSg | /**
             * Address details (Non-Singapore Format)
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */ DataitemAddressUnformatted;
            /**
             * MailAdd
             * Mailing Address of Person
             *
             * **Note:**
             * - address can be either a Singapore address (type: 'SG') or non Singapore address (type: 'Unformatted')
             * - check the `type` discriminator property to differentiate between the two address formats
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            mailadd?: 
            /**
             * Address details (Singapore Format)
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            /**
             * MailAdd
             * Mailing Address of Person
             *
             * **Note:**
             * - address can be either a Singapore address (type: 'SG') or non Singapore address (type: 'Unformatted')
             * - check the `type` discriminator property to differentiate between the two address formats
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */ DataitemAddressSg | /**
             * Address details (Non-Singapore Format)
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */ DataitemAddressUnformatted;
            /**
             * BillAdd
             * Billing Address of Person
             *
             * **Note:**
             * - address can be either a Singapore address (type: 'SG') or non Singapore address (type: 'Unformatted')
             * - check the `type` discriminator property to differentiate between the two address formats
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            billadd?: 
            /**
             * Address details (Singapore Format)
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            /**
             * BillAdd
             * Billing Address of Person
             *
             * **Note:**
             * - address can be either a Singapore address (type: 'SG') or non Singapore address (type: 'Unformatted')
             * - check the `type` discriminator property to differentiate between the two address formats
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */ DataitemAddressSg | /**
             * Address details (Non-Singapore Format)
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */ DataitemAddressUnformatted;
            /**
             * HousingType
             * Housing Type of Person (non-HDB only).
             *
             * **Note 1:** If `hdbtype` is available, this value will be null.
             *
             * **Note 2:** If `housingtype` &  `hdbtype` are unavailable, make this field user editable.
             *
             * Refer to `hdbtype` for detailed HDB type.
             *
             * * '121' - DETACHED HOUSE
             * * '122' - SEMI-DETACHED HOUSE
             * * '123' - TERRACE HOUSE
             * * '131' - CONDOMINIUM
             * * '132' - EXECUTIVE CONDOMINIUM
             * * '139' - APARTMENT
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            housingtype?: {
                /**
                 *
                 * example:
                 * 123
                 */
                code?: "121" | "122" | "123" | "131" | "132" | "139";
                /**
                 *
                 * example:
                 * TERRACE HOUSE
                 */
                desc?: "DETACHED HOUSE" | "SEMI-DETACHED HOUSE" | "TERRACE HOUSE" | "CONDOMINIUM" | "EXECUTIVE CONDOMINIUM" | "APARTMENT";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * HDBType
             * Flat Type of the HDB flat.
             *
             * **Note 1:** that this excludes Rental Flats, Pre-War SIT flat, PSA flat, HUDC flat, Executive Condominium and Shophouse.
             *
             * **Note 2:** If `housingtype` is available, this value will be null.
             *
             * **Note 3:** If `housingtype` &  `hdbtype` are unavailable, make this field user editable.
             *
             * * '111' - 1-ROOM FLAT (HDB)
             * * '112' - 2-ROOM FLAT (HDB)
             * * '113' - 3-ROOM FLAT (HDB)
             * * '114' - 4-ROOM FLAT (HDB)
             * * '115' - 5-ROOM FLAT (HDB)
             * * '116' - EXECUTIVE FLAT (HDB)
             * * '118' - STUDIO APARTMENT (HDB)
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            hdbtype?: {
                /**
                 *
                 * example:
                 * 112
                 */
                code?: "111" | "112" | "113" | "114" | "115" | "116" | "118";
                /**
                 *
                 * example:
                 * 2-ROOM FLAT (HDB)
                 */
                desc?: "1-ROOM FLAT (HDB)" | "2-ROOM FLAT (HDB)" | "3-ROOM FLAT (HDB)" | "4-ROOM FLAT (HDB)" | "5-ROOM FLAT (HDB)" | "EXECUTIVE FLAT (HDB)" | "STUDIO APARTMENT (HDB)";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * HDBOwnership
             * HDB Ownership details
             *
             */
            hdbownership?: {
                /**
                 * Number of Owners. Note that this does not include executors, administrators or trustees.
                 */
                noofowners?: {
                    /**
                     * example:
                     * 2
                     */
                    value?: number;
                };
                /**
                 * Address details (Singapore Format)
                 */
                address?: {
                    /**
                     * Type of Address (SG or Unformatted for non SG)
                     */
                    type?: "SG" | "Unformatted";
                    /**
                     * Block of Address
                     */
                    block?: {
                        /**
                         * example:
                         * 548
                         */
                        value?: string;
                    };
                    /**
                     * Building of Address
                     */
                    building?: {
                        /**
                         * example:
                         *
                         */
                        value?: string;
                    };
                    /**
                     * Floor of Address
                     */
                    floor?: {
                        /**
                         * example:
                         * 09
                         */
                        value?: string;
                    };
                    /**
                     * Unit of Address
                     */
                    unit?: {
                        /**
                         * example:
                         * 128
                         */
                        value?: string;
                    };
                    /**
                     * Street of Address
                     */
                    street?: {
                        /**
                         * example:
                         * BEDOK NORTH AVENUE 1
                         */
                        value?: string;
                    };
                    /**
                     * Postal Code of Address
                     */
                    postal?: {
                        /**
                         * example:
                         * 460548
                         */
                        value?: string;
                    };
                    /**
                     * Country of Address. For AddressSG this will always be "SG".
                     */
                    country?: {
                        code?: string;
                        desc?: string;
                    };
                };
                /**
                 * HDBType
                 * Flat Type of the HDB flat.
                 *
                 * **Note 1:** that this excludes Rental Flats, Pre-War SIT flat, PSA flat, HUDC flat, Executive Condominium and Shophouse.
                 *
                 * **Note 2:** If `housingtype` is available, this value will be null.
                 *
                 * **Note 3:** If `housingtype` &  `hdbtype` are unavailable, make this field user editable.
                 *
                 * * '111' - 1-ROOM FLAT (HDB)
                 * * '112' - 2-ROOM FLAT (HDB)
                 * * '113' - 3-ROOM FLAT (HDB)
                 * * '114' - 4-ROOM FLAT (HDB)
                 * * '115' - 5-ROOM FLAT (HDB)
                 * * '116' - EXECUTIVE FLAT (HDB)
                 * * '118' - STUDIO APARTMENT (HDB)
                 */
                hdbtype?: {
                    /**
                     *
                     * example:
                     * 112
                     */
                    code?: "111" | "112" | "113" | "114" | "115" | "116" | "118";
                    /**
                     *
                     * example:
                     * 2-ROOM FLAT (HDB)
                     */
                    desc?: "1-ROOM FLAT (HDB)" | "2-ROOM FLAT (HDB)" | "3-ROOM FLAT (HDB)" | "4-ROOM FLAT (HDB)" | "5-ROOM FLAT (HDB)" | "EXECUTIVE FLAT (HDB)" | "STUDIO APARTMENT (HDB)";
                };
                /**
                 * Date from which the lease period starts. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                leasecommencementdate?: {
                    /**
                     * example:
                     * 2008-06-13
                     */
                    value?: string;
                };
                /**
                 * Term of lease (in years) for the property computed from the lease commencement date.
                 */
                termoflease?: {
                    /**
                     * example:
                     * 99
                     */
                    value?: number;
                };
                /**
                 * Effective date of flat purchase. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                dateofpurchase?: {
                    /**
                     * example:
                     * 2008-06-13
                     */
                    value?: string;
                };
                /**
                 * Effective date of partial transfer without monetary consideration (e.g. addition, deletion or substitution of a co-owner) for an HDB sold flat.
                 *
                 * For partial transfer of flat where at least one of the current owner remains in the household, the Date of Purchase remains unchanged while the date of transfer of ownership will be updated.
                 *
                 * For outright transfer where there is a total change of all owner(s), only the Date of Purchase will be updated.
                 *
                 * See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14'
                 */
                dateofownershiptransfer?: {
                    /**
                     * example:
                     * 2018-06-13
                     */
                    value?: string;
                };
                /**
                 * The amount of housing loan granted to owner(s) by HDB in SGD.
                 */
                loangranted?: {
                    /**
                     * example:
                     * 310000.01
                     */
                    value?: number;
                };
                /**
                 * The number of years of loan repaymnet opted by owner(s) at the time the loan is first granted to him/her.
                 */
                originalloanrepayment?: {
                    /**
                     * example:
                     * 25
                     */
                    value?: number;
                };
                /**
                 * The remaining term of repayment for the loan in the format `years` + `months`.
                 */
                balanceloanrepayment?: {
                    years?: {
                        /**
                         * example:
                         * 2
                         */
                        value?: number;
                    };
                    months?: {
                        /**
                         * example:
                         * 6
                         */
                        value?: number;
                    };
                };
                /**
                 * The amount of outstanding HDB loan owed by owner(s) in SGD.
                 */
                outstandingloanbalance?: {
                    /**
                     * example:
                     * 50000.01
                     */
                    value?: number;
                };
                /**
                 * The amount of monthly instalment the owner(s) have to pay for his/her loan in SGD.
                 */
                monthlyloaninstalment?: {
                    /**
                     * example:
                     * 1000.01
                     */
                    value?: number;
                };
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            }[];
            /**
             * OwnerPrivate
             * Ownership of Private Property Status of Person (based on IRAS information).
             *
             * * true
             * * false
             * * null (data not available)
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            ownerprivate?: {
                /**
                 * Value of data field.
                 * example:
                 * false
                 */
                value?: boolean;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * Email
             * Email Address of Person.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            email?: {
                /**
                 * Value of data field.
                 * example:
                 * test@gmail.com
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * HomeNo
             * Home Contact Number of Person.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            homeno?: {
                /**
                 * Prefix of Phone Number. Defaults to '+'. If phone number is blank, prefix will be returned as blank.
                 */
                prefix?: {
                    /**
                     * example:
                     * +
                     */
                    value?: string;
                };
                /**
                 * Area Code of Phone Number. Default to '065'. If phone number is blank, code will be returned as blank.
                 */
                areacode?: {
                    /**
                     * example:
                     * 65
                     */
                    value?: string;
                };
                /**
                 * Phone Number.
                 */
                nbr?: {
                    /**
                     * example:
                     * 66132665
                     */
                    value?: string;
                };
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * MobileNo
             * Mobile Number of Person.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            mobileno?: {
                /**
                 * Prefix of Phone Number. Defaults to '+'. If phone number is blank, prefix will be returned as blank.
                 */
                prefix?: {
                    /**
                     * example:
                     * +
                     */
                    value?: string;
                };
                /**
                 * Area Code of Phone Number. Default to '065'. If phone number is blank, code will be returned as blank.
                 */
                areacode?: {
                    /**
                     * example:
                     * 65
                     */
                    value?: string;
                };
                /**
                 * Phone Number.
                 */
                nbr?: {
                    /**
                     * example:
                     * 66132665
                     */
                    value?: string;
                };
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * Marital
             * Marital Status of Person.
             *
             * * '1' - SINGLE
             * * '2' - MARRIED
             * * '3' - WIDOWED
             * * '5' - DIVORCED
             *
             * **Note:** This field must be made **editable** on your digital service form even though `source` is '1' (Government Verified).
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            marital?: {
                /**
                 *
                 * example:
                 * 2
                 */
                code?: "1" | "2" | "3" | "5";
                /**
                 *
                 * example:
                 * MARRIED
                 */
                desc?: "SINGLE" | "MARRIED" | "WIDOWED" | "DIVORCED";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * MarriageCertNo
             * Certificate number of the latest marriage.
             *
             *
             * **Note:** This field must be made **editable** on your digital service form even though `source` is '1' (Government Verified).
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            marriagecertno?: {
                /**
                 * Value of data field.
                 * example:
                 * 123456789012345
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * CountryOfMarriage
             * Country of the latest marriage.
             *
             *
             * **Note:** This field must be made **editable** on your digital service form even though `source` is '1' (Government Verified).
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            countryofmarriage?: {
                /**
                 *
                 * example:
                 * SG
                 */
                code?: string;
                /**
                 *
                 * example:
                 * SINGAPORE
                 */
                desc?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * MarriageDate
             * Latest Marriage Date of Person.
             *
             *
             * **Note:** This field must be made **editable** on your digital service form even though `source` is '1' (Government Verified).
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            marriagedate?: {
                /**
                 * Value of data field.
                 *
                 * See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 * example:
                 * 2007-01-01
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * DivorceDate
             * Last Divorce Date of Person.
             *
             *
             * **Note:** This field must be made **editable** on your digital service form even though `source` is '1' (Government Verified).
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            divorcedate?: {
                /**
                 * Value of data field.
                 *
                 * See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 * example:
                 *
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * ChildrenBirthRecords
             * This refers to only local registered birth records(based on ICA’s electronic Birth Certificate Records from 1985 onwards).
             *
             * This includes adoption of locally registered child.
             *
             * For child below 21, the child’s Birth Cert No, Name, Sex, Race, Dialect, Date of Birth and Time of Birth will be shown.
             *
             * For child above 21, only the child’s Birth Cert Number will be shown.
             */
            childrenbirthrecords?: {
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
                /**
                 * Birth certificate number of child.
                 */
                birthcertno?: {
                    /**
                     * example:
                     * S5562882C
                     */
                    value?: string;
                };
                /**
                 * Full Name of child
                 */
                name?: {
                    /**
                     * example:
                     * Jo Tan Pei Ni
                     */
                    value?: string;
                };
                /**
                 * Han Yu Pin Yin name of child.
                 *
                 * *Presentation Logic - If there is a value to `hanyupinyinname` (i.e. not empty), then `hanyupinyinname` should be displayed in a new line below `name`, and formatted with round brackets i.e. \"(`hanyupinyinname`)\".*
                 */
                hanyupinyinname?: {
                    /**
                     * example:
                     * Cheng Pei Ni
                     */
                    value?: string;
                };
                /**
                 * Alias name of child.
                 *
                 * *Presentation Logic - If there is a value to `aliasname` (i.e. not empty), then `aliasname` should be displayed in a new line below `hanyupinyinname`, and prefixed with the ''@'' symbol i.e. \"@`aliasname`\".*
                 */
                aliasname?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
                /**
                 * Han Yu Pin Yin Alias name of child.
                 *
                 * *Presentation Logic - If there is a value to `hanyupinyinaliasname` (i.e. not empty), then `hanyupinyinaliasname` should be displayed in a new line below `aliasname`, and prefixed with the ''@'' symbol i.e. \"@`hanyupinyinaliasname`\".*
                 */
                hanyupinyinaliasname?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
                /**
                 * Married name of child.
                 *
                 * *Presentation Logic - If there is a value to `marriedname` (i.e. not empty), then `marriedname` should be displayed in a new line below `hanyupinyinaliasname`.*
                 */
                marriedname?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
                /**
                 * Sex of child. Possible values:
                 *
                 * * 'F' - FEMALE
                 * * 'M' - MALE
                 * * 'U' - UNKNOWN
                 */
                sex?: {
                    /**
                     * example:
                     * F
                     */
                    code?: "F" | "M" | "U";
                    /**
                     * example:
                     * FEMALE
                     */
                    desc?: "FEMALE" | "MALE" | "UNKNOWN";
                };
                /**
                 * Race of child.
                 *
                 * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
                 *
                 */
                race?: {
                    /**
                     * example:
                     * CN
                     */
                    code?: string;
                    /**
                     * example:
                     * CHINESE
                     */
                    desc?: string;
                };
                /**
                 * Secondary Race of child.
                 *
                 * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
                 */
                secondaryrace?: {
                    /**
                     * example:
                     *
                     */
                    code?: string;
                    /**
                     * example:
                     *
                     */
                    desc?: string;
                };
                /**
                 * Dialect of child.
                 *
                 * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
                 */
                dialect?: {
                    /**
                     * example:
                     * HK
                     */
                    code?: string;
                    /**
                     * example:
                     * HOKKIEN
                     */
                    desc?: string;
                };
                /**
                 * Life Status of child. Possible values:
                 *
                 * * A - ALIVE
                 * * D - DECEASED
                 */
                lifestatus?: {
                    /**
                     * example:
                     * D
                     */
                    code?: "A" | "D";
                    /**
                     * example:
                     * DECEASED
                     */
                    desc?: "ALIVE" | "DECEASED";
                };
                /**
                 * Date of Birth of child.
                 *
                 * See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                dob?: {
                    /**
                     * example:
                     * 2011-09-10
                     */
                    value?: string;
                };
                /**
                 * Time of Birth of child.
                 *
                 * Format: HHMM
                 */
                tob?: {
                    /**
                     * example:
                     * 0901
                     */
                    value?: string;
                };
            }[];
            /**
             * SponsoredChildrenRecords
             * Details of children sponsored to be SG/PR
             *
             * For child below 21, the child’s Birth Cert No, Name, Sex, Race, Dialect, Date of Birth and Time of Birth will be shown.
             *
             * For child above 21, only the child’s last known NRIC will be shown.
             */
            sponsoredchildrenrecords?: {
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
                /**
                 * NRIC of child
                 */
                nric?: {
                    /**
                     * example:
                     * S5562882C
                     */
                    value?: string;
                };
                /**
                 * Full Name of child
                 */
                name?: {
                    /**
                     * example:
                     * Jo Tan Pei Ni
                     */
                    value?: string;
                };
                /**
                 * Han Yu Pin Yin name of child.
                 */
                hanyupinyinname?: {
                    /**
                     * example:
                     * Cheng Pei Ni
                     */
                    value?: string;
                };
                /**
                 * Alias name of child.
                 */
                aliasname?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
                /**
                 * Han Yu Pin Yin Alias name of child.
                 */
                hanyupinyinaliasname?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
                /**
                 * Married name of child.
                 */
                marriedname?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
                /**
                 * Sex of child. Possible values:
                 *
                 * * 'F' - FEMALE
                 * * 'M' - MALE
                 * * 'U' - UNKNOWN
                 */
                sex?: {
                    /**
                     * example:
                     * F
                     */
                    code?: "F" | "M" | "U";
                    /**
                     * example:
                     * FEMALE
                     */
                    desc?: "FEMALE" | "MALE" | "UNKNOWN";
                };
                /**
                 * Race of child.
                 *
                 * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
                 */
                race?: {
                    /**
                     * example:
                     * CN
                     */
                    code?: string;
                    /**
                     * example:
                     * CHINESE
                     */
                    desc?: string;
                };
                /**
                 * Secondary Race of child.
                 *
                 * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
                 */
                secondaryrace?: {
                    /**
                     * example:
                     *
                     */
                    code?: string;
                    /**
                     * example:
                     *
                     */
                    desc?: string;
                };
                /**
                 * Dialect of child.
                 *
                 * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
                 */
                dialect?: {
                    /**
                     * example:
                     * HK
                     */
                    code?: string;
                    /**
                     * example:
                     * HOKKIEN
                     */
                    desc?: string;
                };
                /**
                 * Date of Birth of child.
                 *
                 * See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                dob?: {
                    /**
                     * example:
                     * 2011-09-10
                     */
                    value?: string;
                };
                /**
                 * BirthCountry
                 * Country of Birth of child.
                 *
                 * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
                 */
                birthcountry?: {
                    /**
                     * example:
                     * SG
                     */
                    code?: string;
                    /**
                     * example:
                     * SINGAPORE
                     */
                    desc?: string;
                };
                /**
                 * Life Status of child. Possible values:
                 *
                 * * A - ALIVE
                 * * D - DECEASED
                 */
                lifestatus?: {
                    /**
                     * example:
                     * A
                     */
                    code?: "A" | "D";
                    /**
                     * example:
                     * ALIVE
                     */
                    desc?: "ALIVE" | "DECEASED";
                };
                /**
                 * ResidentialStatus
                 * Residential Status of child. Possible values:
                 *
                 * * A - ALIEN
                 * * C - CITIZEN
                 * * P - PR
                 * * U - UNKNOWN
                 * * N - NOT APPLICABLE
                 */
                residentialstatus?: {
                    /**
                     * example:
                     * C
                     */
                    code?: "A" | "C" | "P" | "U" | "N";
                    /**
                     * example:
                     * Citizen
                     */
                    desc?: "ALIEN" | "CITIZEN" | "PR" | "UNKNOWN" | "NOT APPLICABLE";
                };
                /**
                 * Nationality of child.
                 *
                 * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
                 */
                nationality?: {
                    /**
                     * example:
                     * SG
                     */
                    code?: string;
                    /**
                     * example:
                     * SINGAPORE CITIZEN
                     */
                    desc?: string;
                };
                /**
                 * Date granted Singapore Citizenship or Permanant Resident
                 *
                 * See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                scprgrantdate?: {
                    /**
                     * example:
                     * 2015-06-13
                     */
                    value?: string;
                };
            }[];
            /**
             * EduLevel
             * Highest Education Level of Person.
             *
             * * '0' - NO FORMAL QUALIFICATION / PRE-PRIMARY / LOWER PRIMARY
             * * '1' - PRIMARY
             * * '2' - LOWER SECONDARY
             * * '3' - SECONDARY
             * * '4' - POST-SECONDARY (NON-TERTIARY): GENERAL & VOCATION
             * * '5' - POLYTECHNIC DIPLOMA
             * * '6' - PROFESSIONAL QUALIFICATION AND OTHER DIPLOMA
             * * '7' - BACHELOR'S OR EQUIVALENT
             * * '8' - POSTGRADUATE DIPLOMA / CERTIFICATE (EXCLUDING MASTER'S AND DOCTORATE)
             * * '9' - MASTER'S AND DOCTORATE OR EQUIVALENT
             * * 'N' - MODULAR CERTIFICATION (NON-AWARD COURSES / NON-FULL QUALIFICATIONS)
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            edulevel?: {
                /**
                 *
                 * example:
                 * 7
                 */
                code?: "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "N";
                /**
                 * example:
                 * BACHELOR'S OR EQUIVALENT
                 */
                desc?: "NO FORMAL QUALIFICATION / PRE-PRIMARY / LOWER PRIMARY" | "PRIMARY" | "LOWER SECONDARY" | "SECONDARY" | "POST-SECONDARY (NON-TERTIARY): GENERAL & VOCATION" | "POLYTECHNIC DIPLOMA" | "PROFESSIONAL QUALIFICATION AND OTHER DIPLOMA" | "BACHELOR'S OR EQUIVALENT" | "POSTGRADUATE DIPLOMA / CERTIFICATE (EXCLUDING MASTER'S AND DOCTORATE)" | "MASTER'S AND DOCTORATE OR EQUIVALENT" | "MODULAR CERTIFICATION (NON-AWARD COURSES / NON-FULL QUALIFICATIONS)";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * GradYear
             * Year of Graduation of Person. Format: YYYY
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            gradyear?: {
                /**
                 * example:
                 * 2006
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * SchoolName
             * Name of School of Person.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            schoolname?: {
                /**
                 * Code value of school name.
                 *
                 * **Note:** Code+desc and value are mutually exclusive.
                 * example:
                 * T07GS3011J
                 */
                code?: string;
                /**
                 * Name of school represented by 'code'
                 *
                 * **Note:** Code+desc and value are mutually exclusive.
                 * example:
                 * SIGLAP SECONDARY SCHOOL
                 */
                desc?: string;
                /**
                 * Free text value of school name.
                 *
                 * **Note:** Code+desc and value are mutually exclusive.
                 * example:
                 *
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * Occupation
             * Occupation of Person.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            occupation?: {
                /**
                 * Code of occupation based on SSOC 2015.
                 *
                 * For full list, refer to SSOC 2015 at https://www.singstat.gov.sg/standards/standards-and-classifications/ssoc.
                 *
                 * For FIN holders, blank will be returned.
                 *
                 * **Note:** Code+Desc and Value are mutually exclusive.
                 * example:
                 * 53201
                 */
                code?: string;
                /**
                 * Description of occupation corresponding to code.
                 *
                 * **Note:** Code+Desc and Value are mutually exclusive.
                 * example:
                 * HEALTHCARE ASSISTANT
                 */
                desc?: string;
                /**
                 * Free text cccupation entered by user
                 * **Note:** Code+Desc and Value are mutually exclusive.
                 * example:
                 *
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * Employment
             * Name of Employer.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            employment?: {
                /**
                 * example:
                 * ALPHA
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * PassType
             * Pass type of a FIN holder. <br/>**Note:** Only applies to a foreigner with a valid pass.
             *
             * * 'RPass' - Work Permit
             * * 'SPass' - S Pass
             * * 'P1Pass' - Employment Pass
             * * 'P2Pass' - Employment Pass
             * * 'QPass' - Employment Pass
             * * 'PEP' - Personalised Employment Pass
             * * 'WHP' - Work Holiday Pass
             * * 'TEP' - Training Employment Pass
             * * 'Entre' - EntrePass
             * * 'DP' - Dependent Pass
             * * 'LTVP' - Long Term Visit Pass
             * * 'LOC' - Letter of Consent
             * * 'MWP' - Miscellaneous Work Pass
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            passtype?: {
                /**
                 * Value of data field.
                 * example:
                 * RPass
                 */
                code?: "RPass" | "SPass" | "P1Pass" | "P2Pass" | "QPass" | "PEP" | "WHP" | "TEP" | "Entre" | "DP" | "LTVP" | "LOC" | "MWP";
                /**
                 * example:
                 * Work Permit
                 */
                desc?: "Work Permit" | "S Pass" | "Employment Pass" | "Employment Pass" | "Employment Pass" | "Personalised Employment Pass" | "Work Holiday Pass" | "Training Employment Pass" | "EntrePass" | "Dependent Pass" | "Long Term Visit Pass" | "Letter of Consent" | "Miscellaneous Work Pass";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * PassStatus
             * Pass status of a FIN holder. <br/>**Note:** Only applies to a foreigner with a valid pass.
             * *	Live
             * *	Approved
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            passstatus?: {
                /**
                 * Value of data field.
                 * example:
                 * Live
                 */
                value?: "Live" | "Approved";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * PassExpiryDate
             * Pass expiry of a foreigner. <br/>**Note:** Only applies to a foreigner with a valid pass.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            passexpirydate?: {
                /**
                 * Value of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 * example:
                 * 2022-12-31
                 */
                value?: string;
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * EmploymentSector
             * Employment Sector of a FIN holder.
             *
             * **Note:** Only applies to a foreigner with a valid work pass.
             *
             * * Construction
             * * Manufacturing
             * * Marine Shipyard
             * * Process
             * * Services
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            employmentsector?: {
                /**
                 * example:
                 * Manufacturing
                 */
                value?: "Construction" | "Manufacturing" | "Marine Shipyard" | "Process" | "Services";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * HouseholdIncome
             * Household Income of Person in SGD.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            householdincome?: {
                /**
                 * upper bound of the range of household income bracket
                 */
                high?: {
                    /**
                     * example:
                     * 5999
                     */
                    value?: number;
                };
                /**
                 * lower bound of the range of household income bracket
                 */
                low?: {
                    /**
                     * example:
                     * 5000
                     */
                    value?: number;
                };
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * **NOTE** Vehicles property is custom set to be array instead of object.
             *
             * Even though the vehicles property is defined as object in the original swagger file, the actual data is returned as array. Moreover the array will allow a person to have multiple vehicles.
             */
            vehicles?: {
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
                /**
                 * Vehicle Registration Number displayed on the vehicle number plates
                 */
                vehicleno?: {
                    /**
                     * example:
                     * SDF1235A
                     */
                    value?: string;
                };
                /**
                 * Type of Vehicles such as 'MOTOR CAR', 'STATION /WAGON/JEEP/LAND ROVER'
                 */
                type?: {
                    /**
                     * example:
                     * PASSENGER MOTOR CAR
                     */
                    value?: string;
                };
                /**
                 * In-Vehicle Unit (IU) number of the device fitted in Singapore-registered vehicles for Electronic Road Pricing (ERP) gantries and Electronic Parking System (EPS) car parks.
                 */
                iulabelno?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
                /**
                 * Vehicle Make such as 'TOYOTA', 'HONDA', 'AUDI'
                 */
                make?: {
                    /**
                     * example:
                     * TOYOTA
                     */
                    value?: string;
                };
                /**
                 * Vehicle Model such as 'COROLLA ALTIS CLASSIC 1.6 CVT', 'HRV 1.5 DX CVT'
                 */
                model?: {
                    /**
                     * example:
                     * COROLLA ALTIS
                     */
                    value?: string;
                };
                /**
                 * Vehicle Chassis Number
                 */
                chassisno?: {
                    /**
                     * example:
                     * ZC11S1735800
                     */
                    value?: string;
                };
                /**
                 * Vehicle Engine Number
                 */
                engineno?: {
                    /**
                     * example:
                     * M13A1837453
                     */
                    value?: string;
                };
                /**
                 * Vehicle Motor Number
                 */
                motorno?: {
                    /**
                     * example:
                     *
                     */
                    value?: string;
                };
                /**
                 * Manufacturing year
                 */
                yearofmanufacture?: {
                    /**
                     * example:
                     * 2010
                     */
                    value?: string;
                };
                /**
                 * Date when vehicle is registered with LTA. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14'
                 */
                firstregistrationdate?: {
                    /**
                     * example:
                     * 2010-06-06
                     */
                    value?: string;
                };
                /**
                 * Date when vehicle is first registered in the country of origin. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14'
                 */
                originalregistrationdate?: {
                    /**
                     * example:
                     * 2010-06-06
                     */
                    value?: string;
                };
                /**
                 * Vehicle Certificate of Entitlement (COE) bid category
                 */
                coecategory?: {
                    /**
                     * example:
                     * A - CAR UP TO 1600CC & 97KW (130BHP)
                     */
                    value?: string;
                };
                /**
                 * Vehicle Certificate of Entitlement (COE) expiry date. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14'
                 */
                coeexpirydate?: {
                    /**
                     * example:
                     * 2020-06-05
                     */
                    value?: string;
                };
                /**
                 * See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14'
                 */
                roadtaxexpirydate?: {
                    /**
                     * example:
                     * 2020-06-05
                     */
                    value?: string;
                };
                /**
                 * Actual Quota Premium (QP) amount payable for the COE upon registration, conversion or COE revalidation in Singapore dollars (SGD). For renewal of COE, the value will contain actual PQP paid.
                 */
                quotapremium?: {
                    /**
                     * example:
                     * 14000.01
                     */
                    value?: number;
                };
                /**
                 * Open Market Value is the value of manufacturer invoice price, freight and insurance in Singapore dollars (SGD).
                 */
                openmarketvalue?: {
                    /**
                     * example:
                     * 25000.01
                     */
                    value?: number;
                };
                /**
                 * CO2 emission rate
                 */
                co2emission?: {
                    /**
                     * example:
                     * 146.01
                     */
                    value?: number;
                };
                /**
                 * Status of the Vehicle.
                 *
                 * * 1 - LIVE
                 * * 2 - DE-REGISTERED
                 */
                status?: {
                    /**
                     * example:
                     * 1
                     */
                    code?: "1" | "2";
                    /**
                     * example:
                     * LIVE
                     */
                    desc?: "LIVE" | "DE-REGISTERED";
                };
                /**
                 * Vehicle Primary Colour (e.g. BLACK)
                 */
                primarycolour?: {
                    /**
                     * example:
                     * BLACK
                     */
                    value?: string;
                };
                /**
                 * Vehicle Primary Colour (e.g. WHITE)
                 */
                secondarycolour?: {
                    /**
                     * example:
                     * WHITE
                     */
                    value?: string;
                };
                /**
                 * Vehicle Attachment 1 (e.g. DISABLED)
                 */
                attachment1?: {
                    /**
                     * example:
                     * DISABLED
                     */
                    value?: string;
                };
                /**
                 * Vehicle Attachment 2 (e.g. WITH SUN ROOF)
                 */
                attachment2?: {
                    /**
                     * example:
                     * WITH SUN ROOF
                     */
                    value?: string;
                };
                /**
                 * Vehicle Attachment 3 (e.g. SIDE CURTAIN)
                 */
                attachment3?: {
                    /**
                     * example:
                     * SIDE CURTAIN
                     */
                    value?: string;
                };
                /**
                 * Vehicle Scheme (e.g. REVISED OFF-PEAK CAR)
                 */
                scheme?: {
                    /**
                     * example:
                     * REVISED OFF-PEAK CAR
                     */
                    value?: string;
                };
                /**
                 * Total Hydro Carbon (THC) emission rate
                 */
                thcemission?: {
                    /**
                     * example:
                     * 1.011001
                     */
                    value?: number;
                };
                /**
                 * Carbon Monoxide emission rate
                 */
                coemission?: {
                    /**
                     * example:
                     * 1.100001
                     */
                    value?: number;
                };
                /**
                 * Nitrogen Oxide (NOx) emission rate.
                 */
                noxemission?: {
                    /**
                     * example:
                     * 0.011001
                     */
                    value?: number;
                };
                /**
                 * Particulates (PM - Atmospheric Particulate Matter) emission rate.
                 */
                pmemission?: {
                    /**
                     * example:
                     * 0.007
                     */
                    value?: number;
                };
                /**
                 * Engine Capacity in cubic centimeter (cc)
                 */
                enginecapacity?: {
                    /**
                     * example:
                     * 1600
                     */
                    value?: number;
                };
                /**
                 * Power Rate. Applicable to Electric and Hybrid vehicles powered by electric motors. Unit is Kilowatt.
                 */
                powerrate?: {
                    /**
                     * example:
                     * 1.41
                     */
                    value?: number;
                };
                /**
                 * Effective Date/Time of Ownership. See "date-time" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14'
                 */
                effectiveownership?: {
                    /**
                     * example:
                     * 2010-08-31T20:12:12+08:00
                     */
                    value?: string;
                };
                /**
                 * Propellant (e.g. Compressed Natural Gas, Diesel, Diesel-CNG, Diesel-Electric, Diesel-Electric (Plug-In), Electric, Gas, Liquefied Petroleum Gas (LPG), Petrol, Petrol-CNG, Petrol-Electric, Petrol-Electric (Plug-In), Petrol-LPG
                 */
                propellant?: {
                    /**
                     * example:
                     * Compressed Natural Gas
                     */
                    value?: string;
                };
                /**
                 * Maximum Unladen Weight in kilograms (kg)
                 */
                maximumunladenweight?: {
                    /**
                     * example:
                     * 1500
                     */
                    value?: number;
                };
                /**
                 * Maximum Laden Weight in kilograms (kg)
                 */
                maximumladenweight?: {
                    /**
                     * example:
                     * 1795
                     */
                    value?: number;
                };
                /**
                 * Minimum PARF Benefit in Singapore dollars (SGD).
                 */
                minimumparfbenefit?: {
                    /**
                     * example:
                     * 8770.01
                     */
                    value?: number;
                };
                /**
                 * Number of Transfer
                 */
                nooftransfers?: {
                    /**
                     * example:
                     * 2
                     */
                    value?: number;
                };
                /**
                 * Vehicle Parking Certificate. Applicable for Heavy Vehicles.
                 */
                vpc?: {
                    /**
                     * example:
                     * 1234567890
                     */
                    value?: string;
                };
            }[];
            /**
             * Driving Licence details of Person.
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            drivinglicence?: {
                /**
                 * Status of Certificate of Merit. Possible values:
                 *
                 * * Y - ELIGIBLE
                 * * N - NOT ELIGIBLE
                 */
                comstatus?: {
                    /**
                     * example:
                     * Y
                     */
                    code?: "Y" | "N";
                    /**
                     *
                     * example:
                     * ELIGIBLE
                     */
                    desc?: "ELIGIBLE" | "NOT ELIGIBLE";
                };
                /**
                 * Total Demerit Points
                 */
                totaldemeritpoints?: {
                    /**
                     * example:
                     * 0
                     */
                    value?: number;
                };
                /**
                 *
                 */
                suspension?: {
                    /**
                     * Suspension Start Date
                     */
                    startdate?: {
                        /**
                         * example:
                         *
                         */
                        value?: string;
                    };
                    /**
                     * Suspension End Date
                     */
                    enddate?: {
                        /**
                         * example:
                         *
                         */
                        value?: string;
                    };
                };
                /**
                 *
                 */
                disqualification?: {
                    /**
                     * Disqualification Start Date
                     */
                    startdate?: {
                        /**
                         * example:
                         *
                         */
                        value?: string;
                    };
                    /**
                     * Disqualification End Date
                     */
                    enddate?: {
                        /**
                         * example:
                         *
                         */
                        value?: string;
                    };
                };
                /**
                 *
                 */
                revocation?: {
                    /**
                     * Revocation Start Date
                     */
                    startdate?: {
                        /**
                         * example:
                         *
                         */
                        value?: string;
                    };
                    /**
                     * Revocation End Date
                     */
                    enddate?: {
                        /**
                         * example:
                         *
                         */
                        value?: string;
                    };
                };
                /**
                 * Provisional Driving Licence (PDL)
                 */
                pdl?: {
                    /**
                     * Validity of PDL. Possible values:
                     *
                     * * V - VALID
                     * * E - EXPIRED
                     * * I - INVALID
                     * * N - NOT HOLDING
                     */
                    validity?: {
                        /**
                         * example:
                         * V
                         */
                        code?: "V" | "E" | "I" | "N";
                        /**
                         *
                         * example:
                         * VALID
                         */
                        desc?: "VALID" | "EXPIRED" | "INVALID" | "NOT HOLDING";
                    };
                    /**
                     * PDL Expiry Date
                     */
                    expirydate?: {
                        /**
                         * example:
                         * 2020-06-15
                         */
                        value?: string;
                    };
                    /**
                     * PDL Classes
                     * example:
                     * [
                     *   {
                     *     "class": {
                     *       "value": "2A"
                     *     }
                     *   },
                     *   {
                     *     "class": {
                     *       "value": "3A"
                     *     }
                     *   }
                     * ]
                     */
                    classes?: {
                        class?: {
                            value?: string;
                        };
                    }[];
                };
                /**
                 * Qualified Driving Licence (QDL)
                 */
                qdl?: {
                    /**
                     * Validity of QDL. Possible values:
                     *
                     * * V - VALID
                     * * E - EXPIRED
                     * * I - INVALID
                     * * N - NOT HOLDING
                     */
                    validity?: {
                        /**
                         * example:
                         * V
                         */
                        code?: "V" | "E" | "I" | "N";
                        /**
                         *
                         * example:
                         * VALID
                         */
                        desc?: "VALID" | "EXPIRED" | "INVALID" | "NOT HOLDING";
                    };
                    /**
                     * QDL Expiry Date
                     */
                    expirydate?: {
                        /**
                         * example:
                         * 2020-06-15
                         */
                        value?: string;
                    };
                    /**
                     * QDL Classes. Includes Issue Date (e.g. 2B, 2018-01-01)
                     * example:
                     * [
                     *   {
                     *     "class": {
                     *       "value": "2A"
                     *     },
                     *     "issuedate": {
                     *       "value": "2018-06-06"
                     *     }
                     *   },
                     *   {
                     *     "class": {
                     *       "value": "3A"
                     *     },
                     *     "issuedate": {
                     *       "value": "2018-06-06"
                     *     }
                     *   }
                     * ]
                     */
                    classes?: {
                        class?: {
                            value?: string;
                        };
                        issuedate?: {
                            value?: string;
                        };
                    }[];
                };
                /**
                 * Serial Number of the Photo Card
                 */
                photocardserialno?: {
                    /**
                     * example:
                     * 115616
                     */
                    value?: string;
                };
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            gstvoucher?: {
                gstregular: {
                    value: number;
                };
                year: {
                    value: number;
                };
                exclusion: {
                    value: boolean;
                };
                gstmedisave: {
                    value: number;
                };
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                gstspecial: {
                    value: number;
                };
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                signup: {
                    value: boolean;
                };
            };
            merdekagen?: {
                eligibility: {
                    value: boolean;
                };
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                quantum: {
                    value: number;
                };
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Message code
                 * * '1' - MGP Eligibility Tag: N
                 * * '2' - MGP Eligibility Tag: Y, Sign-up Tag: Y, Invalid Address Tag: N
                 * * '3' - MGP Eligibility Tag: Y, Sign-up Tag: Y, Invalid Address Tag: Y
                 * * '4' - MGP Eligibility Tag: Y, Sign-up Tag: N, Invalid Address Tag: N
                 * * '5' - MGP Eligibility Tag: Y, Sign-up Tag: N, Invalid Address Tag: Y
                 * * '6' - MGP Eligibility Tag: Y, Opt-Out Tag: Y
                 * * '7' - MGP Eligibility Tag: Y, Sign-up Tag: Y, NIL Status: Y
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                message: {
                    code: "1" | "2" | "3" | "4" | "5" | "6" | "7";
                    desc: "We regret that you are not eligible for the Merdeka Generation Package.  For further enquiries, please contact 1800-2222-888." | "You are eligible for the Merdeka Generation Package. For further enquiries, please contact 1800-2222-888." | "You are eligible for the Merdeka Generation Package. Please call 6391 6100 to update your NRIC address with ICA and then contact 1800-2222-888 to receive your Merdeka Generation card." | "You are eligible for the Merdeka Generation Package. Please contact 1800-2222-888 to receive your Merdeka Generation MediSave top-up." | "You are eligible for the Merdeka Generation Package. Please call 6391 6100 to update your NRIC address with ICA, and then contact 1800-2222-888 to receive your Merdeka Generation card." | "We understand that you have opted out of receiving the benefits under the Merdeka Generation Package. For further enquiries, please contact 1800-2222-888." | "Please contact 1800-2222-888 for further details on your eligibility.";
                };
            };
            pioneergen?: {
                eligibility: {
                    value: boolean;
                };
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                quantum: {
                    value: string;
                };
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Message code
                 *
                 * * '1' - PG Eligibility Tag: N
                 * * '2' - PG Eligibility Tag: Y, Sign-up Tag: Y, Invalid Address Tag: N
                 * * '3' - PG Eligibility Tag: Y, Sign-up Tag: Y, Invalid Address Tag: Y
                 * * '4' - PG Eligibility Tag: Y, Sign-up Tag: N, Invalid Address Tag: N
                 * * '5' - PG Eligibility Tag: Y, Sign-up Tag: N, Invalid Address Tag: Y
                 * * '6' - PG Eligibility Tag: Y, Opt-Out Tag: Y
                 * * '7' - PG Eligibility Tag: Y, Sign-up Tag: Y, NIL Status: Y
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                message: {
                    code: "1" | "2" | "3" | "4" | "5" | "6" | "7";
                    desc: "We regret that you are not eligible for the Pioneer Generation Package.  For further enquiries, please contact 1800-2222-888." | "You are eligible for the Pioneer Generation Package. For further enquiries, please contact 1800-2222-888." | "You are eligible for the Pioneer Generation Package. Please contact 1800-2222-888 to receive your Pioneer Generation card." | "You are eligible for the Pioneer Generation Package. Please contact 1800-2222-888 to start receiving your Pioneer Generation benefits, such as your MediSave top-up." | "You are eligible for the Pioneer Generation Package. Please contact 1800-2222-888 to start receiving your Pioneer Generation benefits." | "We understand that you have opted out of receiving the benefits under the Pioneer Generation Package. For further enquiries, please contact 1800-2222-888." | "Please call 1800-2222-888 to start receiving your PG benefits.";
                };
            };
            silversupport?: {
                eligibility: {
                    value: boolean;
                };
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                amount: {
                    value: number;
                };
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                year: {
                    value: number;
                };
            };
        }
        /**
         * Person instance's details
         */
        interface PersonFinancial {
            /**
             * Summary of latest Notice of Assessment within the past three years.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            "noa-basic"?: {
                /**
                 * Assessable Income
                 */
                amount?: {
                    /**
                     * example:
                     * 100000.01
                     */
                    value?: number;
                };
                /**
                 * The second latest annual assessable income available from IRAS within the past 3 years.
                 */
                yearofassessment?: {
                    /**
                     * example:
                     * 2018
                     */
                    value?: string;
                };
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * Detailed breakdown of latest Notice of Assessment within the past three years.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            noa?: {
                /**
                 * Assessable Income
                 */
                amount?: {
                    /**
                     * example:
                     * 100000.01
                     */
                    value?: number;
                };
                /**
                 * value of data field
                 */
                yearofassessment?: {
                    /**
                     * example:
                     * 2018
                     */
                    value?: string;
                };
                /**
                 * Assessable Income from employment
                 */
                employment?: {
                    /**
                     * example:
                     * 100000.01
                     */
                    value?: number;
                };
                /**
                 * Assessable Income from trade
                 */
                trade?: {
                    /**
                     * example:
                     * 0
                     */
                    value?: number;
                };
                /**
                 * Assessable Income from rent
                 */
                rent?: {
                    /**
                     * example:
                     * 0
                     */
                    value?: number;
                };
                /**
                 * Assessable Income from interest
                 */
                interest?: {
                    /**
                     * example:
                     * 0
                     */
                    value?: number;
                };
                /**
                 * Tax Clearance indicator. This means that tax clearance has been sought by the employer for this NOA assessment. For more information, please refer to [this](https://www.iras.gov.sg/irashome/Businesses/Employers/Tax-Clearance-for-Foreign-SPR-Employees/Getting-Tax-Clearance--A-Step-by-Step-Guide/)
                 */
                taxclearance?: {
                    /**
                     * example:
                     * N
                     */
                    value?: "Y" | "N";
                };
                /**
                 * Type of 'Notice of Assessment' (NOA)
                 */
                category?: {
                    /**
                     * example:
                     * ORIGINAL
                     */
                    value?: "ADDITIONAL" | "AMENDED" | "ORIGINAL" | "REPAYMENT";
                };
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * History of Notice Of Assessment (Basic)
             * Summary of latest 2 Notice of Assessments within the past three years.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            "noahistory-basic"?: {
                noas?: NOABasic[];
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * History of Notice Of Assessment
             * Detailed breakdown of latest 2 Notice of Assessments within the past three years.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            noahistory?: {
                noas?: NOA[];
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * CPFContributions
             * Employer CPF Contributions of Person in SGD. Does not include any non-employer contributions.
             * Maximum past 14 months' of contributions.
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            cpfcontributions?: {
                /**
                 * example:
                 * [
                 *   {
                 *     "date": {
                 *       "value": "2016-12-01"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2016-11"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2016-12-12"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2016-12"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2016-12-21"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2016-12"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-01-01"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2016-12"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-01-12"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-01"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-01-21"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-01"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-02-01"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-01"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-02-12"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-02"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-02-21"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-02"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-03-01"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-02"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-03-12"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-03"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-03-21"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-03"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-04-01"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-03"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-04-12"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-04"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-04-21"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-04"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-05-01"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-04"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-05-12"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-05"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-05-21"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-05"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-06-01"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-05"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-06-12"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-06"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-06-21"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-06"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-07-01"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-06"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-07-12"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-07"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-07-21"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-07"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-08-01"
                 *     },
                 *     "amount": {
                 *       "value": 500
                 *     },
                 *     "month": {
                 *       "value": "2017-07"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-08-12"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-08"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-08-21"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-08"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-09-01"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-08"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-09-12"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-09"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-09-21"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-09"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-10-01"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-09"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-10-12"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-10"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-10-21"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-10"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-11-01"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-10"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-11-12"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-11"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-11-21"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-11"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-12-01"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-11"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-12-12"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-12"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2017-12-21"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-12"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2018-01-01"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2017-12"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2018-01-12"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2018-01"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "date": {
                 *       "value": "2018-01-21"
                 *     },
                 *     "amount": {
                 *       "value": 750
                 *     },
                 *     "month": {
                 *       "value": "2018-01"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   }
                 * ]
                 */
                history?: {
                    /**
                     * Employer who paid the Contribution.
                     */
                    employer?: {
                        /**
                         * example:
                         * Crystal Horse Invest Pte Ltd
                         */
                        value?: string;
                    };
                    /**
                     * Date of Contribution Paid. See "full-date" in http://xml2rfc.ietf.org/public/rfc/htm
                     */
                    date?: {
                        /**
                         * example:
                         * 2017-03-01
                         */
                        value?: string;
                    };
                    /**
                     * Month for which CPF Contribution was paid. Format: YYYY-MM
                     */
                    month?: {
                        /**
                         * example:
                         * 2017-02
                         */
                        value?: string;
                    };
                    /**
                     * Amount of contribution in SGD
                     */
                    amount?: {
                        /**
                         * example:
                         * 500
                         */
                        value?: number;
                    };
                }[];
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * CPFEmployers
             * Employers who paid CPF Contributions. Maximum up to past 14 months.
             *
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            cpfemployers?: {
                /**
                 * example:
                 * [
                 *   {
                 *     "month": {
                 *       "value": "2016-11"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2016-12"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2016-12"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2016-12"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-01"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-01"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-01"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-02"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-02"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-02"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-03"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-03"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-03"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-04"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-04"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-04"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-05"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-05"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-05"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-06"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-06"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-06"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-07"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-07"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-07"
                 *     },
                 *     "employer": {
                 *       "value": "Crystal Horse Invest Pte Ltd"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-08"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-08"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-08"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-09"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-09"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-09"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-10"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-10"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-10"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-11"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-11"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-11"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-12"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-12"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2017-12"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2018-01"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   },
                 *   {
                 *     "month": {
                 *       "value": "2018-01"
                 *     },
                 *     "employer": {
                 *       "value": "Delta Marine Consultants PL"
                 *     }
                 *   }
                 * ]
                 */
                history?: {
                    /**
                     * Employer who paid the Contribution.
                     */
                    employer?: {
                        /**
                         * example:
                         * Crystal Horse Invest Pte Ltd
                         */
                        value?: string;
                    };
                    /**
                     * Month for which CPF Contribution was paid. Format: YYYY-MM
                     */
                    month?: {
                        /**
                         * example:
                         * 2017-03
                         */
                        value?: string;
                    };
                }[];
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
            /**
             * CPFBalances
             * CPF Balances of Person in SGD.
             *
             * 'ra' will not appear in the results if user does not have a Retirement Account.
             * example:
             * {
             *   "classification": "C",
             *   "source": "1",
             *   "lastupdated": "2019-03-26"
             * }
             */
            cpfbalances?: {
                /**
                 * Amount Balance in CPF-MA
                 */
                ma?: {
                    /**
                     * example:
                     * 11470.71
                     */
                    value?: number;
                };
                /**
                 * Amount Balance in CPF-OA
                 */
                oa?: {
                    /**
                     * example:
                     * 1581.48
                     */
                    value?: number;
                };
                /**
                 * Amount Balance in CPF-SA
                 */
                sa?: {
                    /**
                     * example:
                     * 21967.09
                     */
                    value?: number;
                };
                /**
                 * Amount Balance in CPF-RA
                 */
                ra?: {
                    /**
                     * example:
                     * 0.01
                     */
                    value?: number;
                };
                /**
                 * Data classification of data field. Default 'C' - Confidential.
                 */
                classification: "C";
                /**
                 * Source of data.
                 *
                 * * '1' - Government-verified
                 * * '2' - User provided
                 * * '3' - Field is Not Applicable to Person
                 * * '4' - Verified by SingPass
                 *
                 * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
                 */
                source: "1" | "2" | "3" | "4";
                /**
                 * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
                 */
                lastupdated: string;
                /**
                 * Optional flag to indicate if data is unavalable from data source.
                 *
                 * **NOTE:**
                 *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
                 *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
                 *   - If data is available from the data source, this property will not be present.
                 *
                 */
                unavailable: boolean;
            };
        }
        interface PhoneNumLocal {
            /**
             * Prefix of Phone Number. Defaults to '+'. If phone number is blank, prefix will be returned as blank.
             */
            prefix?: {
                /**
                 * example:
                 * +
                 */
                value?: string;
            };
            /**
             * Area Code of Phone Number. Default to '065'. If phone number is blank, code will be returned as blank.
             */
            areacode?: {
                /**
                 * example:
                 * 65
                 */
                value?: string;
            };
            /**
             * Phone Number.
             */
            nbr?: {
                /**
                 * example:
                 * 66132665
                 */
                value?: string;
            };
        }
        interface Pioneergen {
            eligibility: {
                value: boolean;
            };
            /**
             * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
             */
            lastupdated: string;
            quantum: {
                value: string;
            };
            /**
             * Source of data.
             *
             * * '1' - Government-verified
             * * '2' - User provided
             * * '3' - Field is Not Applicable to Person
             * * '4' - Verified by SingPass
             *
             * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
             */
            source: "1" | "2" | "3" | "4";
            /**
             * Data classification of data field. Default 'C' - Confidential.
             */
            classification: "C";
            /**
             * Message code
             *
             * * '1' - PG Eligibility Tag: N
             * * '2' - PG Eligibility Tag: Y, Sign-up Tag: Y, Invalid Address Tag: N
             * * '3' - PG Eligibility Tag: Y, Sign-up Tag: Y, Invalid Address Tag: Y
             * * '4' - PG Eligibility Tag: Y, Sign-up Tag: N, Invalid Address Tag: N
             * * '5' - PG Eligibility Tag: Y, Sign-up Tag: N, Invalid Address Tag: Y
             * * '6' - PG Eligibility Tag: Y, Opt-Out Tag: Y
             * * '7' - PG Eligibility Tag: Y, Sign-up Tag: Y, NIL Status: Y
             *
             * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
             */
            message: {
                code: "1" | "2" | "3" | "4" | "5" | "6" | "7";
                desc: "We regret that you are not eligible for the Pioneer Generation Package.  For further enquiries, please contact 1800-2222-888." | "You are eligible for the Pioneer Generation Package. For further enquiries, please contact 1800-2222-888." | "You are eligible for the Pioneer Generation Package. Please contact 1800-2222-888 to receive your Pioneer Generation card." | "You are eligible for the Pioneer Generation Package. Please contact 1800-2222-888 to start receiving your Pioneer Generation benefits, such as your MediSave top-up." | "You are eligible for the Pioneer Generation Package. Please contact 1800-2222-888 to start receiving your Pioneer Generation benefits." | "We understand that you have opted out of receiving the benefits under the Pioneer Generation Package. For further enquiries, please contact 1800-2222-888." | "Please call 1800-2222-888 to start receiving your PG benefits.";
            };
        }
        /**
         * Race
         * Race of Person.
         *
         * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
         */
        interface Race {
            /**
             * example:
             * CN
             */
            code?: string;
            /**
             * example:
             * CHINESE
             */
            desc?: string;
        }
        /**
         * RegAdd
         * Registered Address of Person
         *
         * **Note:**
         * - address can be either a Singapore address (type: 'SG') or non Singapore address (type: 'Unformatted')
         * - check the `type` discriminator property to differentiate between the two address formats
         *
         */
        type Regadd = 
        /**
         * Address details (Singapore Format)
         * example:
         * {
         *   "classification": "C",
         *   "source": "1",
         *   "lastupdated": "2019-03-26"
         * }
         */
        /**
         * RegAdd
         * Registered Address of Person
         *
         * **Note:**
         * - address can be either a Singapore address (type: 'SG') or non Singapore address (type: 'Unformatted')
         * - check the `type` discriminator property to differentiate between the two address formats
         *
         */ DataitemAddressSg | /**
         * Address details (Non-Singapore Format)
         * example:
         * {
         *   "classification": "C",
         *   "source": "1",
         *   "lastupdated": "2019-03-26"
         * }
         */ DataitemAddressUnformatted;
        /**
         * ResidentialStatus
         * Residential Status of Person. Applicable to Singapore Citizens and Permanent Residents.
         *
         *
         * **Note:** This data item is not applicable for FIN holders i.e. `source` will be '3'.
         * In such cases, the `code` and `desc` properties will be blank or empty string ("").
         *
         * * A - ALIEN
         * * C - CITIZEN
         * * P - PR
         * * U - UNKNOWN
         * * N - NOT APPLICABLE
         * * &lt; BLANK &gt; (for FIN holders only)
         */
        interface Residentialstatus {
            /**
             * example:
             * C
             */
            code?: "A" | "C" | "P" | "U" | "N" | "";
            /**
             * example:
             * CITIZEN
             */
            desc?: "ALIEN" | "CITIZEN" | "PR" | "UNKNOWN" | "NOT APPLICABLE" | "";
        }
        /**
         * SchoolName
         * Name of School of Person.
         */
        interface Schoolname {
            /**
             * Code value of school name.
             *
             * **Note:** Code+desc and value are mutually exclusive.
             * example:
             * T07GS3011J
             */
            code?: string;
            /**
             * Name of school represented by 'code'
             *
             * **Note:** Code+desc and value are mutually exclusive.
             * example:
             * SIGLAP SECONDARY SCHOOL
             */
            desc?: string;
            /**
             * Free text value of school name.
             *
             * **Note:** Code+desc and value are mutually exclusive.
             * example:
             *
             */
            value?: string;
        }
        /**
         * SecondaryRace
         * Secondary Race of Person.
         *
         * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
         */
        interface Secondaryrace {
            /**
             *
             * example:
             * EU
             */
            code?: string;
            /**
             *
             * example:
             * EURASIAN
             */
            desc?: string;
        }
        /**
         * Sex
         * Sex of Person.
         * * 'F' - FEMALE
         * * 'M' - MALE
         * * 'U' - UNKNOWN
         */
        interface Sex {
            /**
             * example:
             * F
             */
            code?: "F" | "M" | "U";
            /**
             *
             * example:
             * FEMALE
             */
            desc?: "FEMALE" | "MALE" | "UNKNOWN";
        }
        interface Silversupport {
            eligibility: {
                value: boolean;
            };
            /**
             * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
             */
            lastupdated: string;
            amount: {
                value: number;
            };
            /**
             * Source of data.
             *
             * * '1' - Government-verified
             * * '2' - User provided
             * * '3' - Field is Not Applicable to Person
             * * '4' - Verified by SingPass
             *
             * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
             */
            source: "1" | "2" | "3" | "4";
            /**
             * Data classification of data field. Default 'C' - Confidential.
             */
            classification: "C";
            year: {
                value: number;
            };
        }
        /**
         * example:
         * {
         *   "classification": "C",
         *   "source": "1",
         *   "lastupdated": "2019-03-26"
         * }
         */
        interface Sponsoredchildrenrecords {
            /**
             * Data classification of data field. Default 'C' - Confidential.
             */
            classification: "C";
            /**
             * Source of data.
             *
             * * '1' - Government-verified
             * * '2' - User provided
             * * '3' - Field is Not Applicable to Person
             * * '4' - Verified by SingPass
             *
             * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
             */
            source: "1" | "2" | "3" | "4";
            /**
             * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
             */
            lastupdated: string;
            /**
             * Optional flag to indicate if data is unavalable from data source.
             *
             * **NOTE:**
             *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
             *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
             *   - If data is available from the data source, this property will not be present.
             *
             */
            unavailable: boolean;
            /**
             * NRIC of child
             */
            nric?: {
                /**
                 * example:
                 * S5562882C
                 */
                value?: string;
            };
            /**
             * Full Name of child
             */
            name?: {
                /**
                 * example:
                 * Jo Tan Pei Ni
                 */
                value?: string;
            };
            /**
             * Han Yu Pin Yin name of child.
             */
            hanyupinyinname?: {
                /**
                 * example:
                 * Cheng Pei Ni
                 */
                value?: string;
            };
            /**
             * Alias name of child.
             */
            aliasname?: {
                /**
                 * example:
                 *
                 */
                value?: string;
            };
            /**
             * Han Yu Pin Yin Alias name of child.
             */
            hanyupinyinaliasname?: {
                /**
                 * example:
                 *
                 */
                value?: string;
            };
            /**
             * Married name of child.
             */
            marriedname?: {
                /**
                 * example:
                 *
                 */
                value?: string;
            };
            /**
             * Sex of child. Possible values:
             *
             * * 'F' - FEMALE
             * * 'M' - MALE
             * * 'U' - UNKNOWN
             */
            sex?: {
                /**
                 * example:
                 * F
                 */
                code?: "F" | "M" | "U";
                /**
                 * example:
                 * FEMALE
                 */
                desc?: "FEMALE" | "MALE" | "UNKNOWN";
            };
            /**
             * Race of child.
             *
             * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
             */
            race?: {
                /**
                 * example:
                 * CN
                 */
                code?: string;
                /**
                 * example:
                 * CHINESE
                 */
                desc?: string;
            };
            /**
             * Secondary Race of child.
             *
             * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
             */
            secondaryrace?: {
                /**
                 * example:
                 *
                 */
                code?: string;
                /**
                 * example:
                 *
                 */
                desc?: string;
            };
            /**
             * Dialect of child.
             *
             * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
             */
            dialect?: {
                /**
                 * example:
                 * HK
                 */
                code?: string;
                /**
                 * example:
                 * HOKKIEN
                 */
                desc?: string;
            };
            /**
             * Date of Birth of child.
             *
             * See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
             */
            dob?: {
                /**
                 * example:
                 * 2011-09-10
                 */
                value?: string;
            };
            /**
             * BirthCountry
             * Country of Birth of child.
             *
             * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
             */
            birthcountry?: {
                /**
                 * example:
                 * SG
                 */
                code?: string;
                /**
                 * example:
                 * SINGAPORE
                 */
                desc?: string;
            };
            /**
             * Life Status of child. Possible values:
             *
             * * A - ALIVE
             * * D - DECEASED
             */
            lifestatus?: {
                /**
                 * example:
                 * A
                 */
                code?: "A" | "D";
                /**
                 * example:
                 * ALIVE
                 */
                desc?: "ALIVE" | "DECEASED";
            };
            /**
             * ResidentialStatus
             * Residential Status of child. Possible values:
             *
             * * A - ALIEN
             * * C - CITIZEN
             * * P - PR
             * * U - UNKNOWN
             * * N - NOT APPLICABLE
             */
            residentialstatus?: {
                /**
                 * example:
                 * C
                 */
                code?: "A" | "C" | "P" | "U" | "N";
                /**
                 * example:
                 * Citizen
                 */
                desc?: "ALIEN" | "CITIZEN" | "PR" | "UNKNOWN" | "NOT APPLICABLE";
            };
            /**
             * Nationality of child.
             *
             * Refer to the [Code reference tables](#section/Support) in the Support section for list of possible values.
             */
            nationality?: {
                /**
                 * example:
                 * SG
                 */
                code?: string;
                /**
                 * example:
                 * SINGAPORE CITIZEN
                 */
                desc?: string;
            };
            /**
             * Date granted Singapore Citizenship or Permanant Resident
             *
             * See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
             */
            scprgrantdate?: {
                /**
                 * example:
                 * 2015-06-13
                 */
                value?: string;
            };
        }
        /**
         * UINFIN
         * Singapore issued identification number of the Person.
         */
        interface Uinfin {
            /**
             * value of the field, should be displayed as it is.
             * example:
             * S1111111D
             */
            value?: string;
        }
        /**
         * **NOTE** Vehicles property is custom set to be array instead of object.
         *
         * Even though the vehicles property is defined as object in the original swagger file, the actual data is returned as array. Moreover the array will allow a person to have multiple vehicles.
         */
        type Vehicles = {
            /**
             * Data classification of data field. Default 'C' - Confidential.
             */
            classification: "C";
            /**
             * Source of data.
             *
             * * '1' - Government-verified
             * * '2' - User provided
             * * '3' - Field is Not Applicable to Person
             * * '4' - Verified by SingPass
             *
             * **Note:** All Government-verified fields must be **non-editable** on your digital service form (some exceptions apply - see individual field descriptions).
             */
            source: "1" | "2" | "3" | "4";
            /**
             * Last updated date of data field. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14
             */
            lastupdated: string;
            /**
             * Optional flag to indicate if data is unavalable from data source.
             *
             * **NOTE:**
             *   - This optional property will be only present with value `true` if there is no data available from the data source; i.e. record not found.
             *   - When this flag is `true`, no other data attributes will be present (other than `classification`, `source`, and `lastupdated`).
             *   - If data is available from the data source, this property will not be present.
             *
             */
            unavailable: boolean;
            /**
             * Vehicle Registration Number displayed on the vehicle number plates
             */
            vehicleno?: {
                /**
                 * example:
                 * SDF1235A
                 */
                value?: string;
            };
            /**
             * Type of Vehicles such as 'MOTOR CAR', 'STATION /WAGON/JEEP/LAND ROVER'
             */
            type?: {
                /**
                 * example:
                 * PASSENGER MOTOR CAR
                 */
                value?: string;
            };
            /**
             * In-Vehicle Unit (IU) number of the device fitted in Singapore-registered vehicles for Electronic Road Pricing (ERP) gantries and Electronic Parking System (EPS) car parks.
             */
            iulabelno?: {
                /**
                 * example:
                 *
                 */
                value?: string;
            };
            /**
             * Vehicle Make such as 'TOYOTA', 'HONDA', 'AUDI'
             */
            make?: {
                /**
                 * example:
                 * TOYOTA
                 */
                value?: string;
            };
            /**
             * Vehicle Model such as 'COROLLA ALTIS CLASSIC 1.6 CVT', 'HRV 1.5 DX CVT'
             */
            model?: {
                /**
                 * example:
                 * COROLLA ALTIS
                 */
                value?: string;
            };
            /**
             * Vehicle Chassis Number
             */
            chassisno?: {
                /**
                 * example:
                 * ZC11S1735800
                 */
                value?: string;
            };
            /**
             * Vehicle Engine Number
             */
            engineno?: {
                /**
                 * example:
                 * M13A1837453
                 */
                value?: string;
            };
            /**
             * Vehicle Motor Number
             */
            motorno?: {
                /**
                 * example:
                 *
                 */
                value?: string;
            };
            /**
             * Manufacturing year
             */
            yearofmanufacture?: {
                /**
                 * example:
                 * 2010
                 */
                value?: string;
            };
            /**
             * Date when vehicle is registered with LTA. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14'
             */
            firstregistrationdate?: {
                /**
                 * example:
                 * 2010-06-06
                 */
                value?: string;
            };
            /**
             * Date when vehicle is first registered in the country of origin. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14'
             */
            originalregistrationdate?: {
                /**
                 * example:
                 * 2010-06-06
                 */
                value?: string;
            };
            /**
             * Vehicle Certificate of Entitlement (COE) bid category
             */
            coecategory?: {
                /**
                 * example:
                 * A - CAR UP TO 1600CC & 97KW (130BHP)
                 */
                value?: string;
            };
            /**
             * Vehicle Certificate of Entitlement (COE) expiry date. See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14'
             */
            coeexpirydate?: {
                /**
                 * example:
                 * 2020-06-05
                 */
                value?: string;
            };
            /**
             * See "full-date" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14'
             */
            roadtaxexpirydate?: {
                /**
                 * example:
                 * 2020-06-05
                 */
                value?: string;
            };
            /**
             * Actual Quota Premium (QP) amount payable for the COE upon registration, conversion or COE revalidation in Singapore dollars (SGD). For renewal of COE, the value will contain actual PQP paid.
             */
            quotapremium?: {
                /**
                 * example:
                 * 14000.01
                 */
                value?: number;
            };
            /**
             * Open Market Value is the value of manufacturer invoice price, freight and insurance in Singapore dollars (SGD).
             */
            openmarketvalue?: {
                /**
                 * example:
                 * 25000.01
                 */
                value?: number;
            };
            /**
             * CO2 emission rate
             */
            co2emission?: {
                /**
                 * example:
                 * 146.01
                 */
                value?: number;
            };
            /**
             * Status of the Vehicle.
             *
             * * 1 - LIVE
             * * 2 - DE-REGISTERED
             */
            status?: {
                /**
                 * example:
                 * 1
                 */
                code?: "1" | "2";
                /**
                 * example:
                 * LIVE
                 */
                desc?: "LIVE" | "DE-REGISTERED";
            };
            /**
             * Vehicle Primary Colour (e.g. BLACK)
             */
            primarycolour?: {
                /**
                 * example:
                 * BLACK
                 */
                value?: string;
            };
            /**
             * Vehicle Primary Colour (e.g. WHITE)
             */
            secondarycolour?: {
                /**
                 * example:
                 * WHITE
                 */
                value?: string;
            };
            /**
             * Vehicle Attachment 1 (e.g. DISABLED)
             */
            attachment1?: {
                /**
                 * example:
                 * DISABLED
                 */
                value?: string;
            };
            /**
             * Vehicle Attachment 2 (e.g. WITH SUN ROOF)
             */
            attachment2?: {
                /**
                 * example:
                 * WITH SUN ROOF
                 */
                value?: string;
            };
            /**
             * Vehicle Attachment 3 (e.g. SIDE CURTAIN)
             */
            attachment3?: {
                /**
                 * example:
                 * SIDE CURTAIN
                 */
                value?: string;
            };
            /**
             * Vehicle Scheme (e.g. REVISED OFF-PEAK CAR)
             */
            scheme?: {
                /**
                 * example:
                 * REVISED OFF-PEAK CAR
                 */
                value?: string;
            };
            /**
             * Total Hydro Carbon (THC) emission rate
             */
            thcemission?: {
                /**
                 * example:
                 * 1.011001
                 */
                value?: number;
            };
            /**
             * Carbon Monoxide emission rate
             */
            coemission?: {
                /**
                 * example:
                 * 1.100001
                 */
                value?: number;
            };
            /**
             * Nitrogen Oxide (NOx) emission rate.
             */
            noxemission?: {
                /**
                 * example:
                 * 0.011001
                 */
                value?: number;
            };
            /**
             * Particulates (PM - Atmospheric Particulate Matter) emission rate.
             */
            pmemission?: {
                /**
                 * example:
                 * 0.007
                 */
                value?: number;
            };
            /**
             * Engine Capacity in cubic centimeter (cc)
             */
            enginecapacity?: {
                /**
                 * example:
                 * 1600
                 */
                value?: number;
            };
            /**
             * Power Rate. Applicable to Electric and Hybrid vehicles powered by electric motors. Unit is Kilowatt.
             */
            powerrate?: {
                /**
                 * example:
                 * 1.41
                 */
                value?: number;
            };
            /**
             * Effective Date/Time of Ownership. See "date-time" in http://xml2rfc.ietf.org/public/rfc/html/rfc3339.html#anchor14'
             */
            effectiveownership?: {
                /**
                 * example:
                 * 2010-08-31T20:12:12+08:00
                 */
                value?: string;
            };
            /**
             * Propellant (e.g. Compressed Natural Gas, Diesel, Diesel-CNG, Diesel-Electric, Diesel-Electric (Plug-In), Electric, Gas, Liquefied Petroleum Gas (LPG), Petrol, Petrol-CNG, Petrol-Electric, Petrol-Electric (Plug-In), Petrol-LPG
             */
            propellant?: {
                /**
                 * example:
                 * Compressed Natural Gas
                 */
                value?: string;
            };
            /**
             * Maximum Unladen Weight in kilograms (kg)
             */
            maximumunladenweight?: {
                /**
                 * example:
                 * 1500
                 */
                value?: number;
            };
            /**
             * Maximum Laden Weight in kilograms (kg)
             */
            maximumladenweight?: {
                /**
                 * example:
                 * 1795
                 */
                value?: number;
            };
            /**
             * Minimum PARF Benefit in Singapore dollars (SGD).
             */
            minimumparfbenefit?: {
                /**
                 * example:
                 * 8770.01
                 */
                value?: number;
            };
            /**
             * Number of Transfer
             */
            nooftransfers?: {
                /**
                 * example:
                 * 2
                 */
                value?: number;
            };
            /**
             * Vehicle Parking Certificate. Applicable for Heavy Vehicles.
             */
            vpc?: {
                /**
                 * example:
                 * 1234567890
                 */
                value?: string;
            };
        }[];
    }
}
//# sourceMappingURL=myinfo-domain.d.ts.map