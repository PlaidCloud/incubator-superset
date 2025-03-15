"use strict";(globalThis.webpackChunksuperset=globalThis.webpackChunksuperset||[]).push([[95],{109433:(e,t,a)=>{a.d(t,{CronPicker:()=>c});var n=a(573126),l=(a(667294),a(738179)),i=a(61988),o=a(751995),r=a(361247),s=a(211965);const d={everyText:(0,i.t)("every"),emptyMonths:(0,i.t)("every month"),emptyMonthDays:(0,i.t)("every day of the month"),emptyMonthDaysShort:(0,i.t)("day of the month"),emptyWeekDays:(0,i.t)("every day of the week"),emptyWeekDaysShort:(0,i.t)("day of the week"),emptyHours:(0,i.t)("every hour"),emptyMinutes:(0,i.t)("every minute"),emptyMinutesForHourPeriod:(0,i.t)("every"),yearOption:(0,i.t)("year"),monthOption:(0,i.t)("month"),weekOption:(0,i.t)("week"),dayOption:(0,i.t)("day"),hourOption:(0,i.t)("hour"),minuteOption:(0,i.t)("minute"),rebootOption:(0,i.t)("reboot"),prefixPeriod:(0,i.t)("Every"),prefixMonths:(0,i.t)("in"),prefixMonthDays:(0,i.t)("on"),prefixWeekDays:(0,i.t)("on"),prefixWeekDaysForMonthAndYearPeriod:(0,i.t)("and"),prefixHours:(0,i.t)("at"),prefixMinutes:(0,i.t)(":"),prefixMinutesForHourPeriod:(0,i.t)("at"),suffixMinutesForHourPeriod:(0,i.t)("minute(s)"),errorInvalidCron:(0,i.t)("Invalid cron expression"),clearButtonText:(0,i.t)("Clear"),weekDays:[(0,i.t)("Sunday"),(0,i.t)("Monday"),(0,i.t)("Tuesday"),(0,i.t)("Wednesday"),(0,i.t)("Thursday"),(0,i.t)("Friday"),(0,i.t)("Saturday")],months:[(0,i.t)("January"),(0,i.t)("February"),(0,i.t)("March"),(0,i.t)("April"),(0,i.t)("May"),(0,i.t)("June"),(0,i.t)("July"),(0,i.t)("August"),(0,i.t)("September"),(0,i.t)("October"),(0,i.t)("November"),(0,i.t)("December")],altWeekDays:[(0,i.t)("SUN"),(0,i.t)("MON"),(0,i.t)("TUE"),(0,i.t)("WED"),(0,i.t)("THU"),(0,i.t)("FRI"),(0,i.t)("SAT")],altMonths:[(0,i.t)("JAN"),(0,i.t)("FEB"),(0,i.t)("MAR"),(0,i.t)("APR"),(0,i.t)("MAY"),(0,i.t)("JUN"),(0,i.t)("JUL"),(0,i.t)("AUG"),(0,i.t)("SEP"),(0,i.t)("OCT"),(0,i.t)("NOV"),(0,i.t)("DEC")]},c=(0,o.iK)((e=>(0,s.tZ)(l.ZP,{getPopupContainer:e=>e.parentElement},(0,s.tZ)(r.default,(0,n.Z)({locale:d},e)))))`
  .react-js-cron-field {
    margin-bottom: 0px;
  }
  .react-js-cron-select:not(.react-js-cron-custom-select) > div:first-of-type,
  .react-js-cron-custom-select {
    border-radius: ${({theme:e})=>e.gridUnit}px;
    background-color: ${({theme:e})=>e.colors.grayscale.light4} !important;
  }
  .react-js-cron-custom-select > div:first-of-type {
    border-radius: ${({theme:e})=>e.gridUnit}px;
  }
  .react-js-cron-custom-select .ant-select-selection-placeholder {
    flex: auto;
  }
  .react-js-cron-custom-select .ant-select-selection-overflow-item {
    align-self: center;
  }
`},112441:(e,t,a)=>{a.d(t,{r:()=>r}),a(667294);var n=a(751995),l=a(840987),i=a(211965);const o=(0,n.iK)(l.Z)`
  .ant-switch-checked {
    background-color: ${({theme:e})=>e.colors.primary.base};
  }
`,r=e=>(0,i.tZ)(o,e)},898978:(e,t,a)=>{a.d(t,{Z:()=>f});var n=a(211965),l=a(667294),i=a(480008),o=a.n(i),r=a(61988),s=a(104715);const d="GMT Standard Time",c="400px",u={"-300-240":["Eastern Standard Time","Eastern Daylight Time"],"-360-300":["Central Standard Time","Central Daylight Time"],"-420-360":["Mountain Standard Time","Mountain Daylight Time"],"-420-420":["Mountain Standard Time - Phoenix","Mountain Standard Time - Phoenix"],"-480-420":["Pacific Standard Time","Pacific Daylight Time"],"-540-480":["Alaska Standard Time","Alaska Daylight Time"],"-600-600":["Hawaii Standard Time","Hawaii Daylight Time"],60120:["Central European Time","Central European Daylight Time"],"00":[d,d],"060":["GMT Standard Time - London","British Summer Time"]},p=o()(),m=o()([2021,1]),T=o()([2021,7]),h=e=>m.tz(e).utcOffset().toString()+T.tz(e).utcOffset().toString(),v=e=>{var t,a;const n=h(e);return(p.tz(e).isDST()?null==(t=u[n])?void 0:t[1]:null==(a=u[n])?void 0:a[0])||e},_=o().tz.countries().map((e=>o().tz.zonesForCountry(e,!0))).flat(),E=[];_.forEach((e=>{E.find((t=>h(t.name)===h(e.name)))||E.push(e)}));const g=E.map((e=>({label:`GMT ${o().tz(p,e.name).format("Z")} (${v(e.name)})`,value:e.name,offsets:h(e.name),timezoneName:e.name}))),b=(e,t)=>o().tz(p,e.timezoneName).utcOffset()-o().tz(p,t.timezoneName).utcOffset();g.sort(b);const N=e=>{var t;return(null==(t=g.find((t=>t.offsets===h(e))))?void 0:t.value)||"Africa/Abidjan"};function f({onTimezoneChange:e,timezone:t,minWidth:a=c}){const i=(0,l.useMemo)((()=>N(t||o().tz.guess())),[t]);return(0,l.useEffect)((()=>{t!==i&&e(i)}),[i,e,t]),(0,n.tZ)(s.Ph,{ariaLabel:(0,r.t)("Timezone selector"),css:(0,n.iv)({minWidth:a},"",""),onChange:t=>e(t),value:i,options:g,sortComparator:b})}},120095:(e,t,a)=>{a.d(t,{j5:()=>H,KL:()=>W,ZP:()=>Y});var n=a(667294),l=a(61988),i=a(751995),o=a(211965),r=a(593185),s=a(431069),d=a(115926),c=a.n(d),u=a(34858),p=a(313322),m=a(9875),T=a(112441),h=a(774069),v=a(898978),_=a(287183),E=a(985633),g=a(414114),b=a(104715),N=a(542878),f=a(418451),Z=a(962948),y=a(409882),x=a(828216),S=a(109433);const O=({value:e,onChange:t})=>{const a=(0,i.Fg)(),r=(0,n.useRef)(null),[s,d]=(0,n.useState)("picker"),c=(0,n.useCallback)((e=>d(e.target.value)),[]),u=(0,n.useCallback)((e=>{var a;t(e),null==(a=r.current)||a.setValue(e)}),[r,t]),p=(0,n.useCallback)((e=>{t(e.target.value)}),[t]),T=(0,n.useCallback)((()=>{var e;t((null==(e=r.current)?void 0:e.input.value)||"")}),[t]),[h,v]=(0,n.useState)();return(0,o.tZ)(n.Fragment,null,(0,o.tZ)(_.Y.Group,{onChange:c,value:s},(0,o.tZ)("div",{className:"inline-container add-margin"},(0,o.tZ)(_.Y,{value:"picker"}),(0,o.tZ)(S.CronPicker,{clearButton:!1,value:e,setValue:u,disabled:"picker"!==s,displayError:"picker"===s,onError:v})),(0,o.tZ)("div",{className:"inline-container add-margin"},(0,o.tZ)(_.Y,{value:"input"}),(0,o.tZ)("span",{className:"input-label"},(0,l.t)("CRON Schedule")),(0,o.tZ)(H,{className:"styled-input"},(0,o.tZ)("div",{className:"input-container"},(0,o.tZ)(m.II,{type:"text",name:"crontab",ref:r,style:h?{borderColor:a.colors.error.base}:{},placeholder:(0,l.t)("CRON expression"),disabled:"input"!==s,onBlur:p,onPressEnter:T}))))))},R=i.iK.div`
  margin-bottom: 10px;

  .input-container {
    textarea {
      height: auto;
    }
  }

  .inline-container {
    margin-bottom: 10px;

    .input-container {
      margin-left: 10px;
    }

    > div {
      margin: 0;
    }

    .delete-button {
      margin-left: 10px;
      padding-top: 3px;
    }
  }
`,A=({setting:e=null,index:t,onUpdate:a,onRemove:r})=>{const{method:s,recipients:d,options:c}=e||{},[u,m]=(0,n.useState)(d||""),T=(0,i.Fg)();return e?(d&&u!==d&&m(d),(0,o.tZ)(R,null,(0,o.tZ)("div",{className:"inline-container"},(0,o.tZ)(H,null,(0,o.tZ)("div",{className:"input-container"},(0,o.tZ)(b.Ph,{ariaLabel:(0,l.t)("Delivery method"),onChange:n=>{if(m(""),a){const l={...e,method:n,recipients:""};a(t,l)}},placeholder:(0,l.t)("Select Delivery Method"),options:(c||[]).map((e=>({label:e,value:e}))),value:s}))),void 0!==s&&r?(0,o.tZ)("span",{role:"button",tabIndex:0,className:"delete-button",onClick:()=>r(t)},(0,o.tZ)(p.Z.Trash,{iconColor:T.colors.grayscale.base})):null),void 0!==s?(0,o.tZ)(H,null,(0,o.tZ)("div",{className:"control-label"},(0,l.t)(s)),(0,o.tZ)("div",{className:"input-container"},(0,o.tZ)("textarea",{name:"recipients",value:u,onChange:n=>{const{target:l}=n;if(m(l.value),a){const n={...e,recipients:l.value};a(t,n)}}})),(0,o.tZ)("div",{className:"helper"},(0,l.t)('Recipients are separated by "," or ";"'))):null)):null},C=["pivot_table_v2","table","paired_ttest"],D=["Email"],I="PNG",U=[{label:(0,l.t)("< (Smaller than)"),value:"<"},{label:(0,l.t)("> (Larger than)"),value:">"},{label:(0,l.t)("<= (Smaller or equal)"),value:"<="},{label:(0,l.t)(">= (Larger or equal)"),value:">="},{label:(0,l.t)("== (Is equal)"),value:"=="},{label:(0,l.t)("!= (Is not equal)"),value:"!="},{label:(0,l.t)("Not null"),value:"not null"}],$=[{label:(0,l.t)("None"),value:0},{label:(0,l.t)("30 days"),value:30},{label:(0,l.t)("60 days"),value:60},{label:(0,l.t)("90 days"),value:90}],X=(0,i.iK)(h.default)`
  max-width: 1200px;
  width: 100%;

  .ant-modal-body {
    overflow: initial;
  }
`,L=(0,i.iK)(y.V)`
  margin-left: ${({theme:e})=>e.gridUnit}px;
`,M=e=>o.iv`
  margin: auto ${2*e.gridUnit}px auto 0;
  color: ${e.colors.grayscale.base};
`,w=i.iK.div`
  display: flex;
  flex-direction: column;

  .control-label {
    margin-top: ${({theme:e})=>e.gridUnit}px;
  }

  .header-section {
    display: flex;
    flex: 0 0 auto;
    align-items: center;
    width: 100%;
    padding: ${({theme:e})=>4*e.gridUnit}px;
    border-bottom: 1px solid ${({theme:e})=>e.colors.grayscale.light2};
  }

  .column-section {
    display: flex;
    flex: 1 1 auto;

    .column {
      flex: 1 1 auto;
      min-width: calc(33.33% - ${({theme:e})=>8*e.gridUnit}px);
      padding: ${({theme:e})=>4*e.gridUnit}px;

      .async-select {
        margin: 10px 0 20px;
      }

      &.condition {
        border-right: 1px solid ${({theme:e})=>e.colors.grayscale.light2};
      }

      &.message {
        border-left: 1px solid ${({theme:e})=>e.colors.grayscale.light2};
      }
    }
  }

  .inline-container {
    display: flex;
    flex-direction: row;
    align-items: center;
    &.wrap {
      flex-wrap: wrap;
    }

    > div {
      flex: 1 1 auto;
    }

    &.add-margin {
      margin-bottom: 5px;
    }

    .styled-input {
      margin: 0 0 0 10px;

      input {
        flex: 0 0 auto;
      }
    }
  }
`,P=i.iK.div`
  display: flex;
  align-items: center;
  margin: ${({theme:e})=>2*e.gridUnit}px auto
    ${({theme:e})=>4*e.gridUnit}px auto;

  h4 {
    margin: 0;
  }

  .required {
    margin-left: ${({theme:e})=>e.gridUnit}px;
    color: ${({theme:e})=>e.colors.error.base};
  }
`,k=i.iK.div`
  display: flex;
  align-items: center;
  margin-top: 10px;

  .switch-label {
    margin-left: 10px;
  }
`,H=i.iK.div`
  flex: 1;
  margin-top: 0;

  input::-webkit-outer-spin-button,
  input::-webkit-inner-spin-button {
    -webkit-appearance: none;
    margin: 0;
  }
  input[type='number'] {
    -moz-appearance: textfield;
  }

  .helper {
    display: block;
    color: ${({theme:e})=>e.colors.grayscale.base};
    font-size: ${({theme:e})=>e.typography.sizes.s}px;
    padding: ${({theme:e})=>e.gridUnit}px 0;
    text-align: left;
  }

  .required {
    margin-left: ${({theme:e})=>e.gridUnit/2}px;
    color: ${({theme:e})=>e.colors.error.base};
  }

  .input-container {
    display: flex;
    align-items: center;

    > div {
      width: 100%;
    }

    label {
      display: flex;
      margin-right: ${({theme:e})=>2*e.gridUnit}px;
    }

    i {
      margin: 0 ${({theme:e})=>e.gridUnit}px;
    }
  }

  input,
  textarea {
    flex: 1 1 auto;
  }

  input[disabled] {
    color: ${({theme:e})=>e.colors.grayscale.base};
  }

  textarea {
    height: 300px;
    resize: none;
  }

  input::placeholder,
  textarea::placeholder {
    color: ${({theme:e})=>e.colors.grayscale.light1};
  }

  textarea,
  input[type='text'],
  input[type='number'] {
    padding: ${({theme:e})=>e.gridUnit}px
      ${({theme:e})=>2*e.gridUnit}px;
    border-style: none;
    border: 1px solid ${({theme:e})=>e.colors.grayscale.light2};
    border-radius: ${({theme:e})=>e.gridUnit}px;

    &[name='description'] {
      flex: 1 1 auto;
    }
  }

  .input-label {
    margin-left: 10px;
  }
`,z=(0,i.iK)(_.Y)`
  display: block;
  line-height: ${({theme:e})=>7*e.gridUnit}px;
`,j=(0,i.iK)(_.Y.Group)`
  margin-left: ${({theme:e})=>5.5*e.gridUnit}px;
`,G=(0,i.iK)(b.r4)`
  margin-top: ${({theme:e})=>2*e.gridUnit}px;
`,q=i.iK.div`
  color: ${({theme:e})=>e.colors.primary.dark1};
  cursor: pointer;

  i {
    margin-right: ${({theme:e})=>2*e.gridUnit}px;
  }

  &.disabled {
    color: ${({theme:e})=>e.colors.grayscale.light1};
    cursor: default;
  }
`,K=i.iK.div`
  .inline-container .input-container {
    margin-left: 0;
  }
`,F=e=>o.iv`
  margin-right: ${3*e.gridUnit}px;
`,W={ADD_NOTIFICATION_METHOD_TEXT:(0,l.t)("Add notification method"),ADD_DELIVERY_METHOD_TEXT:(0,l.t)("Add delivery method"),SAVE_TEXT:(0,l.t)("Save"),ADD_TEXT:(0,l.t)("Add"),EDIT_REPORT_TEXT:(0,l.t)("Edit Report"),EDIT_ALERT_TEXT:(0,l.t)("Edit Alert"),ADD_REPORT_TEXT:(0,l.t)("Add Report"),ADD_ALERT_TEXT:(0,l.t)("Add Alert"),REPORT_NAME_TEXT:(0,l.t)("Report name"),ALERT_NAME_TEXT:(0,l.t)("Alert name"),OWNERS_TEXT:(0,l.t)("Owners"),DESCRIPTION_TEXT:(0,l.t)("Description"),ACTIVE_TEXT:(0,l.t)("Active"),ALERT_CONDITION_TEXT:(0,l.t)("Alert condition"),DATABASE_TEXT:(0,l.t)("Database"),SQL_QUERY_TEXT:(0,l.t)("SQL Query"),SQL_QUERY_TOOLTIP:(0,l.t)("The result of this query should be a numeric-esque value"),TRIGGER_ALERT_IF_TEXT:(0,l.t)("Trigger Alert If..."),CONDITION_TEXT:(0,l.t)("Condition"),VALUE_TEXT:(0,l.t)("Value"),REPORT_SCHEDULE_TEXT:(0,l.t)("Report schedule"),ALERT_CONDITION_SCHEDULE_TEXT:(0,l.t)("Alert condition schedule"),TIMEZONE_TEXT:(0,l.t)("Timezone"),SCHEDULE_SETTINGS_TEXT:(0,l.t)("Schedule settings"),LOG_RETENTION_TEXT:(0,l.t)("Log retention"),WORKING_TIMEOUT_TEXT:(0,l.t)("Working timeout"),TIME_IN_SECONDS_TEXT:(0,l.t)("Time in seconds"),SECONDS_TEXT:(0,l.t)("seconds"),GRACE_PERIOD_TEXT:(0,l.t)("Grace period"),MESSAGE_CONTENT_TEXT:(0,l.t)("Message content"),DASHBOARD_TEXT:(0,l.t)("Dashboard"),CHART_TEXT:(0,l.t)("Chart"),SEND_AS_PNG_TEXT:(0,l.t)("Send as PNG"),SEND_AS_CSV_TEXT:(0,l.t)("Send as CSV"),SEND_AS_TEXT:(0,l.t)("Send as text"),IGNORE_CACHE_TEXT:(0,l.t)("Ignore cache when generating report"),CUSTOM_SCREENSHOT_WIDTH_TEXT:(0,l.t)("Screenshot width"),CUSTOM_SCREENSHOT_WIDTH_PLACEHOLDER_TEXT:(0,l.t)("Input custom width in pixels"),NOTIFICATION_METHOD_TEXT:(0,l.t)("Notification method")},V=({status:e="active",onClick:t})=>"hidden"===e?null:(0,o.tZ)(q,{className:e,onClick:()=>{"disabled"!==e&&t()}},(0,o.tZ)("i",{className:"fa fa-plus"})," ","active"===e?W.ADD_NOTIFICATION_METHOD_TEXT:W.ADD_DELIVERY_METHOD_TEXT),Y=(0,g.ZP)((({addDangerToast:e,onAdd:t,onHide:a,show:i,alert:d=null,isReport:h=!1,addSuccessToast:g})=>{var y,S,R,q,Y,B,Q,J;const ee=(0,x.v9)((e=>e.user)),te=(0,f.c)(),ae=(null==te?void 0:te.ALERT_REPORTS_NOTIFICATION_METHODS)||D,[ne,le]=(0,n.useState)(!0),[ie,oe]=(0,n.useState)(),[re,se]=(0,n.useState)(!0),[de,ce]=(0,n.useState)("dashboard"),[ue,pe]=(0,n.useState)(I),[me,Te]=(0,n.useState)(!1),[he,ve]=(0,n.useState)(!1);(0,n.useEffect)((()=>{ve("dashboard"===de||"chart"===de&&"PNG"===ue)}),[de,ue]);const[_e,Ee]=(0,n.useState)(!1),[ge,be]=(0,n.useState)([]),[Ne,fe]=(0,n.useState)([]),[Ze,ye]=(0,n.useState)([]),[xe,Se]=(0,n.useState)(""),Oe=null!==d,Re="chart"===de&&((0,r.cr)(r.TT.ALERTS_ATTACH_REPORTS)||h),[Ae,Ce]=(0,n.useState)("active"),[De,Ie]=(0,n.useState)([]),{ALERT_REPORTS_DEFAULT_WORKING_TIMEOUT:Ue,ALERT_REPORTS_DEFAULT_CRON_VALUE:$e,ALERT_REPORTS_DEFAULT_RETENTION:Xe}=(0,x.v9)((e=>{var t,a,n,l;const i=null==(t=e.common)?void 0:t.conf;return{ALERT_REPORTS_DEFAULT_WORKING_TIMEOUT:null!=(a=null==i?void 0:i.ALERT_REPORTS_DEFAULT_WORKING_TIMEOUT)?a:3600,ALERT_REPORTS_DEFAULT_CRON_VALUE:null!=(n=null==i?void 0:i.ALERT_REPORTS_DEFAULT_CRON_VALUE)?n:"0 * * * *",ALERT_REPORTS_DEFAULT_RETENTION:null!=(l=null==i?void 0:i.ALERT_REPORTS_DEFAULT_RETENTION)?l:90}})),Le={active:!0,creation_method:"alerts_reports",crontab:$e,log_retention:Xe,working_timeout:Ue,name:"",owners:[],recipients:[],sql:"",validator_config_json:{},validator_type:"",force_screenshot:!1,grace_period:void 0},Me=(e,t)=>{const a=De.slice();a[e]=t,Ie(a),void 0!==t.method&&"hidden"!==Ae&&Ce("active")},we=e=>{const t=De.slice();t.splice(e,1),Ie(t),Ce("active")},{state:{loading:Pe,resource:ke,error:He},fetchResource:ze,createResource:je,updateResource:Ge,clearError:qe}=(0,u.LE)("report",(0,l.t)("report"),e),Ke=()=>{qe(),se(!0),a(),Ie([]),oe({...Le}),Ce("active")},Fe=(0,n.useMemo)((()=>(e="",t,a)=>{const n=c().encode({filter:e,page:t,page_size:a});return s.Z.get({endpoint:`/api/v1/report/related/created_by?q=${n}`}).then((e=>({data:e.json.result.map((e=>({value:e.value,label:e.text}))),totalCount:e.json.count})))}),[]),We=(0,n.useCallback)((e=>{const t=e||(null==ie?void 0:ie.database);if(!t||t.label)return null;let a;return ge.forEach((e=>{e.value!==t.value&&e.value!==t.id||(a=e)})),a}),[null==ie?void 0:ie.database,ge]),Ve=(e,t)=>{oe((a=>({...a,[e]:t})))},Ye=(0,n.useMemo)((()=>(e="",t,a)=>{const n=c().encode({filter:e,page:t,page_size:a});return s.Z.get({endpoint:`/api/v1/report/related/database?q=${n}`}).then((e=>{const t=e.json.result.map((e=>({value:e.value,label:e.text})));return be(t),{data:t,totalCount:e.json.count}}))}),[]),Be=(null==ie?void 0:ie.database)&&!ie.database.label;(0,n.useEffect)((()=>{Be&&Ve("database",We())}),[Be,We]);const Qe=(0,n.useMemo)((()=>(e="",t,a)=>{const n=c().encode_uri({filter:e,page:t,page_size:a});return s.Z.get({endpoint:`/api/v1/report/related/dashboard?q=${n}`}).then((e=>{const t=e.json.result.map((e=>({value:e.value,label:e.text})));return fe(t),{data:t,totalCount:e.json.count}}))}),[]),Je=e=>{const t=e||(null==ie?void 0:ie.dashboard);if(!t||t.label)return null;let a;return Ne.forEach((e=>{e.value!==t.value&&e.value!==t.id||(a=e)})),a},et=(0,n.useCallback)((e=>{const t=e||(null==ie?void 0:ie.chart);if(!t||t.label)return null;let a;return Ze.forEach((e=>{e.value!==t.value&&e.value!==t.id||(a=e)})),a}),[Ze,null==ie?void 0:ie.chart]),tt=(null==ie?void 0:ie.chart)&&!(null!=ie&&ie.chart.label);(0,n.useEffect)((()=>{tt&&Ve("chart",et())}),[et,tt]);const at=(0,n.useMemo)((()=>(e="",t,a)=>{const n=c().encode_uri({filter:e,page:t,page_size:a});return s.Z.get({endpoint:`/api/v1/report/related/chart?q=${n}`}).then((e=>{const t=e.json.result.map((e=>({value:e.value,label:e.text})));return ye(t),{data:t,totalCount:e.json.count}}))}),[]),nt=e=>{const{target:{type:t,value:a,name:n}}=e,l="number"===t?parseInt(a,10)||null:a;Ve(n,l)},lt=e=>{const{target:t}=e,a=+t.value;Ve(t.name,0===a?void 0:a?Math.max(a,1):a)};(0,n.useEffect)((()=>{if(Oe&&(null==ie||!ie.id||(null==d?void 0:d.id)!==ie.id||re&&i)){if(null!==(null==d?void 0:d.id)&&!Pe&&!He){const e=d.id||0;ze(e)}}else!Oe&&(!ie||ie.id||re&&i)&&(oe({...Le,owners:ee?[{value:ee.userId,label:`${ee.firstName} ${ee.lastName}`}]:[]}),Ie([]),Ce("active"))}),[d]),(0,n.useEffect)((()=>{if(ke){const e=(ke.recipients||[]).map((e=>{const t="string"==typeof e.recipient_config_json?JSON.parse(e.recipient_config_json):{};return{method:e.type,recipients:t.target||e.recipient_config_json,options:ae}}));Ie(e),Ce(e.length===ae.length?"hidden":"active"),ce(ke.chart?"chart":"dashboard"),pe(ke.chart&&ke.report_format||I);const t="string"==typeof ke.validator_config_json?JSON.parse(ke.validator_config_json):ke.validator_config_json;Ee("not null"===ke.validator_type),ke.chart&&Se(ke.chart.viz_type),Te(ke.force_screenshot),oe({...ke,chart:ke.chart?et(ke.chart)||{value:ke.chart.id,label:ke.chart.slice_name}:void 0,dashboard:ke.dashboard?Je(ke.dashboard)||{value:ke.dashboard.id,label:ke.dashboard.dashboard_title}:void 0,database:ke.database?We(ke.database)||{value:ke.database.id,label:ke.database.database_name}:void 0,owners:((null==d?void 0:d.owners)||[]).map((e=>({value:e.value||e.id,label:e.label||`${e.first_name} ${e.last_name}`}))),validator_config_json:"not null"===ke.validator_type?{op:"not null"}:t})}}),[ke]);const it=ie||{};return(0,n.useEffect)((()=>{var e,t,a,n,l,i;null!=ie&&null!=(e=ie.name)&&e.length&&null!=ie&&null!=(t=ie.owners)&&t.length&&null!=ie&&null!=(a=ie.crontab)&&a.length&&void 0!==(null==ie?void 0:ie.working_timeout)&&("dashboard"===de&&null!=ie&&ie.dashboard||"chart"===de&&null!=ie&&ie.chart)&&(()=>{if(!De.length)return!1;let e=!1;return De.forEach((t=>{var a;t.method&&null!=(a=t.recipients)&&a.length&&(e=!0)})),e})()&&(h||ie.database&&null!=(n=ie.sql)&&n.length&&(_e||null!=(l=ie.validator_config_json)&&l.op)&&(_e||void 0!==(null==(i=ie.validator_config_json)?void 0:i.threshold)))?le(!1):le(!0)}),[it.name,it.owners,it.database,it.sql,it.validator_config_json,it.crontab,it.working_timeout,it.dashboard,it.chart,de,De,_e]),re&&i&&se(!1),(0,o.tZ)(X,{className:"no-content-padding",responsive:!0,disablePrimaryButton:ne,onHandledPrimaryAction:()=>{var e,a,n;const i=[];De.forEach((e=>{e.method&&e.recipients.length&&i.push({recipient_config_json:{target:e.recipients},type:e.method})}));const o="chart"===de&&!h,r={...ie,type:h?"Report":"Alert",force_screenshot:o||me,validator_type:_e?"not null":"operator",validator_config_json:_e?{}:null==ie?void 0:ie.validator_config_json,chart:"chart"===de?null==ie||null==(e=ie.chart)?void 0:e.value:null,dashboard:"dashboard"===de?null==ie||null==(a=ie.dashboard)?void 0:a.value:null,custom_width:he?null==ie?void 0:ie.custom_width:void 0,database:null==ie||null==(n=ie.database)?void 0:n.value,owners:((null==ie?void 0:ie.owners)||[]).map((e=>e.value||e.id)),recipients:i,report_format:"dashboard"===de?I:ue||I};if(r.recipients&&!r.recipients.length&&delete r.recipients,r.context_markdown="string",Oe){if(null!=ie&&ie.id){const e=ie.id;delete r.id,delete r.created_by,delete r.last_eval_dttm,delete r.last_state,delete r.last_value,delete r.last_value_row_json,Ge(e,r).then((e=>{e&&(g((0,l.t)("%s updated",r.type)),t&&t(),Ke())}))}}else ie&&je(r).then((e=>{e&&(g((0,l.t)("%s updated",r.type)),t&&t(e),Ke())}))},onHide:Ke,primaryButtonName:Oe?W.SAVE_TEXT:W.ADD_TEXT,show:i,width:"100%",maxWidth:"1450px",title:(0,o.tZ)("h4",null,Oe?(0,o.tZ)(p.Z.EditAlt,{css:M}):(0,o.tZ)(p.Z.PlusLarge,{css:M}),Oe&&h?W.EDIT_REPORT_TEXT:Oe?W.EDIT_ALERT_TEXT:h?W.ADD_REPORT_TEXT:W.ADD_ALERT_TEXT)},(0,o.tZ)(w,null,(0,o.tZ)("div",{className:"header-section"},(0,o.tZ)(H,null,(0,o.tZ)("div",{className:"control-label"},h?W.REPORT_NAME_TEXT:W.ALERT_NAME_TEXT,(0,o.tZ)("span",{className:"required"},"*")),(0,o.tZ)("div",{className:"input-container"},(0,o.tZ)("input",{type:"text",name:"name",value:ie?ie.name:"",placeholder:h?W.REPORT_NAME_TEXT:W.ALERT_NAME_TEXT,onChange:nt,css:F}))),(0,o.tZ)(H,null,(0,o.tZ)("div",{className:"control-label"},W.OWNERS_TEXT,(0,o.tZ)("span",{className:"required"},"*")),(0,o.tZ)("div",{className:"input-container"},(0,o.tZ)(b.qb,{ariaLabel:W.OWNERS_TEXT,allowClear:!0,name:"owners",mode:"multiple",value:(null==ie?void 0:ie.owners)||[],options:Fe,onChange:e=>{Ve("owners",e||[])},css:F}))),(0,o.tZ)(H,null,(0,o.tZ)("div",{className:"control-label"},W.DESCRIPTION_TEXT),(0,o.tZ)("div",{className:"input-container"},(0,o.tZ)("input",{type:"text",name:"description",value:ie&&ie.description||"",placeholder:W.DESCRIPTION_TEXT,onChange:nt,css:F}))),(0,o.tZ)(k,null,(0,o.tZ)(T.r,{onChange:e=>{Ve("active",e)},checked:!ie||ie.active}),(0,o.tZ)("div",{className:"switch-label"},W.ACTIVE_TEXT))),(0,o.tZ)("div",{className:"column-section"},!h&&(0,o.tZ)("div",{className:"column condition"},(0,o.tZ)(P,null,(0,o.tZ)("h4",null,W.ALERT_CONDITION_TEXT)),(0,o.tZ)(H,null,(0,o.tZ)("div",{className:"control-label"},W.DATABASE_TEXT,(0,o.tZ)("span",{className:"required"},"*")),(0,o.tZ)("div",{className:"input-container"},(0,o.tZ)(b.qb,{ariaLabel:W.DATABASE_TEXT,name:"source",value:null!=ie&&null!=(y=ie.database)&&y.label&&null!=ie&&null!=(S=ie.database)&&S.value?{value:ie.database.value,label:ie.database.label}:void 0,options:Ye,onChange:e=>{Ve("database",e||[])}}))),(0,o.tZ)(H,null,(0,o.tZ)("div",{className:"control-label"},W.SQL_QUERY_TEXT,(0,o.tZ)(L,{tooltip:W.SQL_QUERY_TOOLTIP}),(0,o.tZ)("span",{className:"required"},"*")),(0,o.tZ)(N.Z,{name:"sql",language:"sql",offerEditInModal:!1,minLines:15,maxLines:15,onChange:e=>{Ve("sql",e||"")},readOnly:!1,initialValue:null==ke?void 0:ke.sql,key:null==ie?void 0:ie.id})),(0,o.tZ)("div",{className:"inline-container wrap"},(0,o.tZ)(H,null,(0,o.tZ)("div",{className:"control-label",css:F},W.TRIGGER_ALERT_IF_TEXT,(0,o.tZ)("span",{className:"required"},"*")),(0,o.tZ)("div",{className:"input-container"},(0,o.tZ)(b.Ph,{ariaLabel:W.CONDITION_TEXT,onChange:e=>{var t;Ee("not null"===e);const a={op:e,threshold:ie?null==(t=ie.validator_config_json)?void 0:t.threshold:void 0};Ve("validator_config_json",a)},placeholder:"Condition",value:(null==ie||null==(R=ie.validator_config_json)?void 0:R.op)||void 0,options:U,css:F}))),(0,o.tZ)(H,null,(0,o.tZ)("div",{className:"control-label"},W.VALUE_TEXT,(0,o.tZ)("span",{className:"required"},"*")),(0,o.tZ)("div",{className:"input-container"},(0,o.tZ)("input",{type:"number",name:"threshold",disabled:_e,value:void 0!==(null==ie||null==(q=ie.validator_config_json)?void 0:q.threshold)?ie.validator_config_json.threshold:"",placeholder:W.VALUE_TEXT,onChange:e=>{var t;const{target:a}=e,n={op:ie?null==(t=ie.validator_config_json)?void 0:t.op:void 0,threshold:a.value};Ve("validator_config_json",n)}}))))),(0,o.tZ)("div",{className:"column schedule"},(0,o.tZ)(P,null,(0,o.tZ)("h4",null,h?W.REPORT_SCHEDULE_TEXT:W.ALERT_CONDITION_SCHEDULE_TEXT),(0,o.tZ)("span",{className:"required"},"*")),(0,o.tZ)(O,{value:(null==ie?void 0:ie.crontab)||"",onChange:e=>Ve("crontab",e)}),(0,o.tZ)("div",{className:"control-label"},W.TIMEZONE_TEXT),(0,o.tZ)("div",{className:"input-container",css:e=>(e=>o.iv`
  margin: ${3*e.gridUnit}px 0;
`)(e)},(0,o.tZ)(v.Z,{onTimezoneChange:e=>{Ve("timezone",e)},timezone:null==ie?void 0:ie.timezone,minWidth:"100%"})),(0,o.tZ)(P,null,(0,o.tZ)("h4",null,W.SCHEDULE_SETTINGS_TEXT)),(0,o.tZ)(H,null,(0,o.tZ)("div",{className:"control-label"},W.LOG_RETENTION_TEXT,(0,o.tZ)("span",{className:"required"},"*")),(0,o.tZ)("div",{className:"input-container"},(0,o.tZ)(b.Ph,{ariaLabel:W.LOG_RETENTION_TEXT,placeholder:W.LOG_RETENTION_TEXT,onChange:e=>{Ve("log_retention",e)},value:"number"==typeof(null==ie?void 0:ie.log_retention)?null==ie?void 0:ie.log_retention:Xe,options:$,sortComparator:(0,E.mj)("value")}))),(0,o.tZ)(H,null,(0,o.tZ)("div",{className:"control-label"},W.WORKING_TIMEOUT_TEXT,(0,o.tZ)("span",{className:"required"},"*")),(0,o.tZ)("div",{className:"input-container"},(0,o.tZ)("input",{type:"number",min:"1",name:"working_timeout",value:(null==ie?void 0:ie.working_timeout)||"",placeholder:W.TIME_IN_SECONDS_TEXT,onChange:lt}),(0,o.tZ)("span",{className:"input-label"},W.SECONDS_TEXT))),!h&&(0,o.tZ)(H,null,(0,o.tZ)("div",{className:"control-label"},W.GRACE_PERIOD_TEXT),(0,o.tZ)("div",{className:"input-container"},(0,o.tZ)("input",{type:"number",min:"1",name:"grace_period",value:(null==ie?void 0:ie.grace_period)||"",placeholder:W.TIME_IN_SECONDS_TEXT,onChange:lt}),(0,o.tZ)("span",{className:"input-label"},W.SECONDS_TEXT)))),(0,o.tZ)("div",{className:"column message"},(0,o.tZ)(P,null,(0,o.tZ)("h4",null,W.MESSAGE_CONTENT_TEXT),(0,o.tZ)("span",{className:"required"},"*")),(0,o.tZ)(_.Y.Group,{onChange:e=>{const{target:t}=e;Te(!1),setTimeout((()=>ce(t.value)),200)},value:de},(0,o.tZ)(z,{value:"dashboard"},W.DASHBOARD_TEXT),(0,o.tZ)(z,{value:"chart"},W.CHART_TEXT)),"chart"===de?(0,o.tZ)(b.qb,{ariaLabel:W.CHART_TEXT,name:"chart",value:null!=ie&&null!=(Y=ie.chart)&&Y.label&&null!=ie&&null!=(B=ie.chart)&&B.value?{value:ie.chart.value,label:ie.chart.label}:void 0,options:at,onChange:e=>{(e=>{s.Z.get({endpoint:`/api/v1/chart/${e.value}`}).then((e=>Se(e.json.result.viz_type)))})(e),Ve("chart",e||void 0),Ve("dashboard",null)}}):(0,o.tZ)(b.qb,{ariaLabel:W.DASHBOARD_TEXT,name:"dashboard",value:null!=ie&&null!=(Q=ie.dashboard)&&Q.label&&null!=ie&&null!=(J=ie.dashboard)&&J.value?{value:ie.dashboard.value,label:ie.dashboard.label}:void 0,options:Qe,onChange:e=>{Ve("dashboard",e||void 0),Ve("chart",null)}}),Re&&(0,o.tZ)(n.Fragment,null,(0,o.tZ)("div",{className:"inline-container"},(0,o.tZ)(j,{onChange:e=>{const{target:t}=e;pe(t.value)},value:ue},(0,o.tZ)(z,{value:"PNG"},W.SEND_AS_PNG_TEXT),(0,o.tZ)(z,{value:"CSV"},W.SEND_AS_CSV_TEXT),C.includes(xe)&&(0,o.tZ)(z,{value:"TEXT"},W.SEND_AS_TEXT)))),he&&(0,o.tZ)(H,null,(0,o.tZ)("div",{className:"control-label",css:Z.yk},W.CUSTOM_SCREENSHOT_WIDTH_TEXT),(0,o.tZ)("div",{className:"input-container"},(0,o.tZ)(m.Rn,{type:"number",name:"custom_width",value:(null==ie?void 0:ie.custom_width)||void 0,min:600,max:2400,placeholder:W.CUSTOM_SCREENSHOT_WIDTH_PLACEHOLDER_TEXT,onChange:e=>{Ve("custom_width",e)}}))),(h||"dashboard"===de)&&(0,o.tZ)("div",{className:"inline-container"},(0,o.tZ)(G,{className:"checkbox",checked:me,onChange:e=>{Te(e.target.checked)}},W.IGNORE_CACHE_TEXT)),(0,o.tZ)(P,null,(0,o.tZ)("h4",null,W.NOTIFICATION_METHOD_TEXT),(0,o.tZ)("span",{className:"required"},"*")),De.map(((e,t)=>(0,o.tZ)(K,null,(0,o.tZ)(A,{setting:e,index:t,key:`NotificationMethod-${t}`,onUpdate:Me,onRemove:we})))),(0,o.tZ)(V,{status:Ae,onClick:()=>{const e=De.slice();e.push({recipients:"",options:ae}),Ie(e),Ce(e.length===ae.length?"hidden":"disabled")}})))))}))},962948:(e,t,a)=>{a.d(t,{E5:()=>Z,G:()=>h,Ks:()=>f,Mv:()=>p,OD:()=>_,Su:()=>E,aQ:()=>N,gH:()=>y,gt:()=>v,kq:()=>b,nn:()=>u,oA:()=>d,oo:()=>m,xZ:()=>T,yk:()=>g,zV:()=>c});var n=a(751995),l=a(211965),i=a(774069),o=a(835932),r=a(287183),s=a(109433);const d=(0,n.iK)(i.default)`
  .ant-modal-body {
    padding: 0;
  }
`,c=n.iK.div`
  padding: ${({theme:e})=>`${3*e.gridUnit}px ${4*e.gridUnit}px ${2*e.gridUnit}px`};
  label {
    font-size: ${({theme:e})=>e.typography.sizes.s}px;
    color: ${({theme:e})=>e.colors.grayscale.light1};
  }
`,u=n.iK.div`
  border-top: 1px solid ${({theme:e})=>e.colors.grayscale.light2};
  padding: ${({theme:e})=>`${4*e.gridUnit}px ${4*e.gridUnit}px ${6*e.gridUnit}px`};
  .ant-select {
    width: 100%;
  }
  .control-label {
    font-size: ${({theme:e})=>e.typography.sizes.s}px;
    color: ${({theme:e})=>e.colors.grayscale.light1};
  }
`,p=n.iK.span`
  span {
    margin-right: ${({theme:e})=>2*e.gridUnit}px;
    vertical-align: middle;
  }
  .text {
    vertical-align: middle;
  }
`,m=n.iK.div`
  margin-bottom: ${({theme:e})=>7*e.gridUnit}px;

  h4 {
    margin-bottom: ${({theme:e})=>3*e.gridUnit}px;
  }
`,T=(0,n.iK)(s.CronPicker)`
  margin-bottom: ${({theme:e})=>3*e.gridUnit}px;
  width: ${({theme:e})=>120*e.gridUnit}px;
`,h=n.iK.p`
  color: ${({theme:e})=>e.colors.error.base};
`,v=l.iv`
  margin-bottom: 0;
`,_=(0,n.iK)(o.Z)`
  width: ${({theme:e})=>40*e.gridUnit}px;
`,E=e=>l.iv`
  margin: ${3*e.gridUnit}px 0 ${2*e.gridUnit}px;
`,g=e=>l.iv`
  margin: ${3*e.gridUnit}px 0 ${2*e.gridUnit}px;
`,b=e=>l.iv`
  margin: ${3*e.gridUnit}px 0;
`,N=n.iK.div`
  margin: ${({theme:e})=>8*e.gridUnit}px 0
    ${({theme:e})=>4*e.gridUnit}px;
`,f=(0,n.iK)(r.Y)`
  display: block;
  line-height: ${({theme:e})=>8*e.gridUnit}px;
`,Z=(0,n.iK)(r.Y.Group)`
  margin-left: ${({theme:e})=>.5*e.gridUnit}px;
`,y=e=>l.iv`
  border: ${e.colors.error.base} 1px solid;
  padding: ${4*e.gridUnit}px;
  margin: ${4*e.gridUnit}px;
  margin-top: 0;
  color: ${e.colors.error.dark2};
  .ant-alert-message {
    font-size: ${e.typography.sizes.m}px;
    font-weight: bold;
  }
  .ant-alert-description {
    font-size: ${e.typography.sizes.m}px;
    line-height: ${4*e.gridUnit}px;
    .ant-alert-icon {
      margin-right: ${2.5*e.gridUnit}px;
      font-size: ${e.typography.sizes.l}px;
      position: relative;
      top: ${e.gridUnit/4}px;
    }
  }
`}}]);
//# sourceMappingURL=6cbe2b4c5d742030466d.chunk.js.map