"use strict";(globalThis.webpackChunksuperset=globalThis.webpackChunksuperset||[]).push([[7177],{554070:(e,t,l)=>{l.d(t,{w:()=>r}),l(667294);var a=l(358593),n=l(83379),i=l(61988),o=l(211965);const r=({user:e,date:t})=>{const l=(0,o.tZ)("span",{className:"no-wrap"},t);if(e){const t=(0,n.Z)(e),r=(0,i.t)("Modified by: %s",t);return(0,o.tZ)(a.u,{title:r,placement:"bottom"},l)}return l}},606065:(e,t,l)=>{l.r(t),l.d(t,{default:()=>B});var a=l(751995),n=l(61988),i=l(431069),o=l(667294),r=l(419259),s=l(313322),u=l(593139),d=l(414114),c=l(358593),p=l(586074),h=l(115926),m=l.n(h),g=l(34858),f=l(211965),b=l(774069),y=l(281315),v=l(9875),Z=l(784101),w=l(49238),k=l(608272);const x=[{label:(0,n.t)("Regular"),value:"Regular"},{label:(0,n.t)("Base"),value:"Base"}];var _;!function(e){e.REGULAR="Regular",e.BASE="Base"}(_||(_={}));const T=f.iv`
  margin: 0;

  .ant-input {
    margin: 0;
  }
`,R=(0,a.iK)(b.default)`
  max-width: 1200px;
  min-width: min-content;
  width: 100%;
  .ant-modal-footer {
    white-space: nowrap;
  }
`,N=e=>f.iv`
  margin: auto ${2*e.gridUnit}px auto 0;
  color: ${e.colors.grayscale.base};
`,S=a.iK.div`
  display: flex;
  flex-direction: column;
  padding: ${({theme:e})=>`${3*e.gridUnit}px ${4*e.gridUnit}px ${2*e.gridUnit}px`};

  label,
  .control-label {
    display: inline-block;
    font-size: ${({theme:e})=>e.typography.sizes.s}px;
    color: ${({theme:e})=>e.colors.grayscale.base};
    vertical-align: middle;
  }

  .info-solid-small {
    vertical-align: middle;
    padding-bottom: ${({theme:e})=>e.gridUnit/2}px;
  }
`,$=a.iK.div`
  display: flex;
  flex-direction: column;
  margin: ${({theme:e})=>e.gridUnit}px;
  margin-bottom: ${({theme:e})=>4*e.gridUnit}px;

  .input-container {
    display: flex;
    align-items: center;

    > div {
      width: 100%;
    }
  }

  input,
  textarea {
    flex: 1 1 auto;
  }

  .required {
    margin-left: ${({theme:e})=>e.gridUnit/2}px;
    color: ${({theme:e})=>e.colors.error.base};
  }
`,E=(0,a.iK)(v.Kx)`
  resize: none;
  margin-top: ${({theme:e})=>e.gridUnit}px;
`,C={name:"",filter_type:_.REGULAR,tables:[],roles:[],clause:"",group_key:"",description:""},A=function(e){const{rule:t,addDangerToast:l,addSuccessToast:a,onHide:r,show:u}=e,[d,c]=(0,o.useState)({...C}),[p,h]=(0,o.useState)(!0),b=null!==t,{state:{loading:v,resource:A,error:D},fetchResource:F,createResource:H,updateResource:L,clearError:B}=(0,g.LE)("rowlevelsecurity",(0,n.t)("rowlevelsecurity"),l),q=(e,t)=>{c((l=>({...l,[e]:t})))},z=(0,o.useCallback)((()=>{var e,t;if(!A)return null;const l=[],a=[];return null==(e=A.tables)||e.forEach((e=>{l.push({key:e.id,label:e.schema?`${e.schema}.${e.table_name}`:e.table_name,value:e.id})})),null==(t=A.roles)||t.forEach((e=>{a.push({key:e.id,label:e.name,value:e.id})})),{tables:l,roles:a}}),[null==A?void 0:A.tables,null==A?void 0:A.roles]);(0,o.useEffect)((()=>{b?null===(null==t?void 0:t.id)||v||D||F(t.id):c({...C})}),[t]),(0,o.useEffect)((()=>{if(A){c({...A,id:null==t?void 0:t.id});const e=z();q("tables",(null==e?void 0:e.tables)||[]),q("roles",(null==e?void 0:e.roles)||[])}}),[A]);const M=d||{};(0,o.useEffect)((()=>{var e;null!=d&&d.name&&null!=d&&d.clause&&null!=(e=d.tables)&&e.length?h(!1):h(!0)}),[M.name,M.clause,null==M?void 0:M.tables]);const U=e=>{q(e.name,e.value)},K=()=>{B(),c({...C}),r()},P=(0,o.useMemo)((()=>(e="",t,l)=>{const a=m().encode({filter:e,page:t,page_size:l});return i.Z.get({endpoint:`/api/v1/rowlevelsecurity/related/tables?q=${a}`}).then((e=>({data:e.json.result.map((e=>({label:e.text,value:e.value}))),totalCount:e.json.count})))}),[]),G=(0,o.useMemo)((()=>(e="",t,l)=>{const a=m().encode({filter:e,page:t,page_size:l});return i.Z.get({endpoint:`/api/v1/rowlevelsecurity/related/roles?q=${a}`}).then((e=>({data:e.json.result.map((e=>({label:e.text,value:e.value}))),totalCount:e.json.count})))}),[]);return(0,f.tZ)(R,{className:"no-content-padding",responsive:!0,show:u,onHide:K,primaryButtonName:b?(0,n.t)("Save"):(0,n.t)("Add"),disablePrimaryButton:p,onHandledPrimaryAction:()=>{var e,t;const l=[],i=[];null==(e=d.tables)||e.forEach((e=>l.push(e.key))),null==(t=d.roles)||t.forEach((e=>i.push(e.key)));const o={...d,tables:l,roles:i};if(b&&d.id){const e=d.id;delete o.id,L(e,o).then((e=>{e&&(a("Rule updated"),K())}))}else d&&H(o).then((e=>{e&&(a((0,n.t)("Rule added")),K())}))},width:"30%",maxWidth:"1450px",title:(0,f.tZ)("h4",null,b?(0,f.tZ)(s.Z.EditAlt,{css:N}):(0,f.tZ)(s.Z.PlusLarge,{css:N}),b?(0,n.t)("Edit Rule"):(0,n.t)("Add Rule"))},(0,f.tZ)(S,null,(0,f.tZ)("div",{className:"main-section"},(0,f.tZ)($,null,(0,f.tZ)(w.QA,{id:"name",name:"name",className:"labeled-input",value:d?d.name:"",required:!0,validationMethods:{onChange:({target:e})=>U(e)},css:T,label:(0,n.t)("Rule Name"),tooltipText:(0,n.t)("The name of the rule must be unique"),hasTooltip:!0})),(0,f.tZ)($,null,(0,f.tZ)("div",{className:"control-label"},(0,n.t)("Filter Type")," ",(0,f.tZ)(k.Z,{tooltip:(0,n.t)("Regular filters add where clauses to queries if a user belongs to a role referenced in the filter, base filters apply filters to all queries except the roles defined in the filter, and can be used to define what users can see if no RLS filters within a filter group apply to them.")})),(0,f.tZ)("div",{className:"input-container"},(0,f.tZ)(y.Z,{name:"filter_type",ariaLabel:(0,n.t)("Filter Type"),placeholder:(0,n.t)("Filter Type"),onChange:e=>{q("filter_type",e)},value:null==d?void 0:d.filter_type,options:x}))),(0,f.tZ)($,null,(0,f.tZ)("div",{className:"control-label"},(0,n.t)("Datasets")," ",(0,f.tZ)("span",{className:"required"},"*"),(0,f.tZ)(k.Z,{tooltip:(0,n.t)("These are the datasets this filter will be applied to.")})),(0,f.tZ)("div",{className:"input-container"},(0,f.tZ)(Z.Z,{ariaLabel:(0,n.t)("Tables"),mode:"multiple",onChange:e=>{q("tables",e||[])},value:(null==d?void 0:d.tables)||[],options:P}))),(0,f.tZ)($,null,(0,f.tZ)("div",{className:"control-label"},d.filter_type===_.BASE?(0,n.t)("Excluded roles"):(0,n.t)("Roles")," ",(0,f.tZ)(k.Z,{tooltip:(0,n.t)("For regular filters, these are the roles this filter will be applied to. For base filters, these are the roles that the filter DOES NOT apply to, e.g. Admin if admin should see all data.")})),(0,f.tZ)("div",{className:"input-container"},(0,f.tZ)(Z.Z,{ariaLabel:(0,n.t)("Roles"),mode:"multiple",onChange:e=>{q("roles",e||[])},value:(null==d?void 0:d.roles)||[],options:G}))),(0,f.tZ)($,null,(0,f.tZ)(w.QA,{id:"group_key",name:"group_key",value:d?d.group_key:"",validationMethods:{onChange:({target:e})=>U(e)},css:T,label:(0,n.t)("Group Key"),hasTooltip:!0,tooltipText:(0,n.t)("Filters with the same group key will be ORed together within the group, while different filter groups will be ANDed together. Undefined group keys are treated as unique groups, i.e. are not grouped together. For example, if a table has three filters, of which two are for departments Finance and Marketing (group key = 'department'), and one refers to the region Europe (group key = 'region'), the filter clause would apply the filter (department = 'Finance' OR department = 'Marketing') AND (region = 'Europe').")})),(0,f.tZ)($,null,(0,f.tZ)("div",{className:"control-label"},(0,f.tZ)(w.QA,{id:"clause",name:"clause",value:d?d.clause:"",required:!0,validationMethods:{onChange:({target:e})=>U(e)},css:T,label:(0,n.t)("Clause"),hasTooltip:!0,tooltipText:(0,n.t)("This is the condition that will be added to the WHERE clause. For example, to only return rows for a particular client, you might define a regular filter with the clause `client_id = 9`. To display no rows unless a user belongs to a RLS filter role, a base filter can be created with the clause `1 = 0` (always false).")}))),(0,f.tZ)($,null,(0,f.tZ)("div",{className:"control-label"},(0,n.t)("Description")),(0,f.tZ)("div",{className:"input-container"},(0,f.tZ)(E,{rows:4,name:"description",value:d?d.description:"",onChange:e=>U(e.target)}))))))};var D=l(440768),F=l(554070),H=l(400012);const L=a.iK.div`
  color: ${({theme:e})=>e.colors.grayscale.base};
`,B=(0,d.ZP)((function(e){const{addDangerToast:t,addSuccessToast:l,user:a}=e,[d,h]=(0,o.useState)(!1),[b,y]=(0,o.useState)(null),{state:{loading:v,resourceCount:Z,resourceCollection:w,bulkSelectEnabled:k},hasPerm:x,fetchData:_,refreshData:T,toggleBulkSelect:R}=(0,g.Yi)("rowlevelsecurity",(0,n.t)("Row Level Security"),t,!0,void 0,void 0,!0);function N(e){y(e),h(!0)}function S(){y(null),h(!1),T()}const $=x("can_write"),E=x("can_write"),C=x("can_export"),B=(0,o.useMemo)((()=>[{accessor:"name",Header:(0,n.t)("Name")},{accessor:"filter_type",Header:(0,n.t)("Filter Type"),size:"xl"},{accessor:"group_key",Header:(0,n.t)("Group Key"),size:"xl"},{accessor:"clause",Header:(0,n.t)("Clause")},{Cell:({row:{original:{changed_on_delta_humanized:e,changed_by:t}}})=>(0,f.tZ)(F.w,{date:e,user:t}),Header:(0,n.t)("Last modified"),accessor:"changed_on_delta_humanized",size:"xl"},{Cell:({row:{original:e}})=>(0,f.tZ)(L,{className:"actions"},$&&(0,f.tZ)(r.Z,{title:(0,n.t)("Please confirm"),description:(0,f.tZ)(o.Fragment,null,(0,n.t)("Are you sure you want to delete")," ",(0,f.tZ)("b",null,e.name)),onConfirm:()=>function({id:e,name:t},l,a,o){return i.Z.delete({endpoint:`/api/v1/rowlevelsecurity/${e}`}).then((()=>{l(),a((0,n.t)("Deleted %s",t))}),(0,D.v$)((e=>o((0,n.t)("There was an issue deleting %s: %s",t,e)))))}(e,T,l,t)},(e=>(0,f.tZ)(c.u,{id:"delete-action-tooltip",title:(0,n.t)("Delete"),placement:"bottom"},(0,f.tZ)("span",{role:"button",tabIndex:0,className:"action-button",onClick:e},(0,f.tZ)(s.Z.Trash,null))))),E&&(0,f.tZ)(c.u,{id:"edit-action-tooltip",title:(0,n.t)("Edit"),placement:"bottom"},(0,f.tZ)("span",{role:"button",tabIndex:0,className:"action-button",onClick:()=>N(e)},(0,f.tZ)(s.Z.EditAlt,null)))),Header:(0,n.t)("Actions"),id:"actions",hidden:!E&&!$&&!C,disableSortBy:!0},{accessor:H.J.changed_by,hidden:!0}]),[a.userId,E,$,C,x,T,t,l]),q={title:(0,n.t)("No Rules yet"),image:"filter-results.svg",buttonAction:()=>N(null),buttonText:E?(0,f.tZ)(o.Fragment,null,(0,f.tZ)("i",{className:"fa fa-plus"})," ","Rule"," "):null},z=(0,o.useMemo)((()=>[{Header:(0,n.t)("Name"),key:"search",id:"name",input:"search",operator:u.p.startsWith},{Header:(0,n.t)("Filter Type"),key:"filter_type",id:"filter_type",input:"select",operator:u.p.equals,unfilteredLabel:(0,n.t)("Any"),selects:[{label:(0,n.t)("Regular"),value:"Regular"},{label:(0,n.t)("Base"),value:"Base"}]},{Header:(0,n.t)("Group Key"),key:"search",id:"group_key",input:"search",operator:u.p.startsWith},{Header:(0,n.t)("Modified by"),key:"changed_by",id:"changed_by",input:"select",operator:u.p.relationOneMany,unfilteredLabel:(0,n.t)("All"),fetchSelects:(0,D.tm)("rowlevelsecurity","changed_by",(0,D.v$)((e=>(0,n.t)("An error occurred while fetching dataset datasource values: %s",e))),a),paginate:!0}]),[a]),M=[{id:"changed_on_delta_humanized",desc:!0}],U=[];return $&&(U.push({name:(0,f.tZ)(o.Fragment,null,(0,f.tZ)("i",{className:"fa fa-plus"})," ",(0,n.t)("Rule")),buttonStyle:"primary",onClick:()=>N(null)}),U.push({name:(0,n.t)("Bulk select"),buttonStyle:"secondary","data-test":"bulk-select",onClick:R})),(0,f.tZ)(o.Fragment,null,(0,f.tZ)(p.Z,{name:(0,n.t)("Row Level Security"),buttons:U}),(0,f.tZ)(r.Z,{title:(0,n.t)("Please confirm"),description:(0,n.t)("Are you sure you want to delete the selected rules?"),onConfirm:function(e){const a=e.map((({id:e})=>e));return i.Z.delete({endpoint:`/api/v1/rowlevelsecurity/?q=${m().encode(a)}`}).then((()=>{T(),l((0,n.t)("Deleted"))}),(0,D.v$)((e=>t((0,n.t)("There was an issue deleting rules: %s",e)))))}},(e=>{const a=[];return $&&a.push({key:"delete",name:(0,n.t)("Delete"),type:"danger",onSelect:e}),(0,f.tZ)(o.Fragment,null,(0,f.tZ)(A,{rule:b,addDangerToast:t,onHide:S,addSuccessToast:l,show:d}),(0,f.tZ)(u.Z,{className:"rls-list-view",bulkActions:a,bulkSelectEnabled:k,disableBulkSelect:R,columns:B,count:Z,data:w,emptyState:q,fetchData:_,filters:z,initialSort:M,loading:v,addDangerToast:t,addSuccessToast:l,refreshData:()=>{},pageSize:25}))})))}))},83379:(e,t,l)=>{function a(e){return e?`${e.first_name} ${e.last_name}`:""}l.d(t,{Z:()=>a})}}]);
//# sourceMappingURL=1187d3b98d847d684a46.chunk.js.map