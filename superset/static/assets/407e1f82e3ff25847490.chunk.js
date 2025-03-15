"use strict";(globalThis.webpackChunksuperset=globalThis.webpackChunksuperset||[]).push([[5656],{554070:(e,t,a)=>{a.d(t,{w:()=>r}),a(667294);var s=a(358593),l=a(83379),n=a(61988),i=a(211965);const r=({user:e,date:t})=>{const a=(0,i.tZ)("span",{className:"no-wrap"},t);if(e){const t=(0,l.Z)(e),r=(0,n.t)("Modified by: %s",t);return(0,i.tZ)(s.u,{title:r,placement:"bottom"},a)}return a}},727989:(e,t,a)=>{a.d(t,{Z:()=>m});var s=a(667294),l=a(751995),n=a(61988),i=a(835932),r=a(774069),o=a(104715),d=a(34858),u=a(762921),c=a(211965);const p=l.iK.div`
  display: block;
  color: ${({theme:e})=>e.colors.grayscale.base};
  font-size: ${({theme:e})=>e.typography.sizes.s}px;
`,h=l.iK.div`
  padding-bottom: ${({theme:e})=>2*e.gridUnit}px;
  padding-top: ${({theme:e})=>2*e.gridUnit}px;

  & > div {
    margin: ${({theme:e})=>e.gridUnit}px 0;
  }

  &.extra-container {
    padding-top: 8px;
  }

  .confirm-overwrite {
    margin-bottom: ${({theme:e})=>2*e.gridUnit}px;
  }

  .input-container {
    display: flex;
    align-items: center;

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

  textarea {
    height: 160px;
    resize: none;
  }

  input::placeholder,
  textarea::placeholder {
    color: ${({theme:e})=>e.colors.grayscale.light1};
  }

  textarea,
  input[type='text'],
  input[type='number'] {
    padding: ${({theme:e})=>1.5*e.gridUnit}px
      ${({theme:e})=>2*e.gridUnit}px;
    border-style: none;
    border: 1px solid ${({theme:e})=>e.colors.grayscale.light2};
    border-radius: ${({theme:e})=>e.gridUnit}px;

    &[name='name'] {
      flex: 0 1 auto;
      width: 40%;
    }

    &[name='sqlalchemy_uri'] {
      margin-right: ${({theme:e})=>3*e.gridUnit}px;
    }
  }
`,m=({resourceName:e,resourceLabel:t,passwordsNeededMessage:a,confirmOverwriteMessage:l,onModelImport:m,show:g,onHide:y,passwordFields:Z=[],setPasswordFields:b=(()=>{}),sshTunnelPasswordFields:v=[],setSSHTunnelPasswordFields:w=(()=>{}),sshTunnelPrivateKeyFields:f=[],setSSHTunnelPrivateKeyFields:S=(()=>{}),sshTunnelPrivateKeyPasswordFields:_=[],setSSHTunnelPrivateKeyPasswordFields:k=(()=>{})})=>{const[x,P]=(0,s.useState)(!0),[T,N]=(0,s.useState)({}),[C,$]=(0,s.useState)(!1),[E,D]=(0,s.useState)(!1),[H,F]=(0,s.useState)([]),[I,O]=(0,s.useState)(!1),[A,R]=(0,s.useState)(),[U,B]=(0,s.useState)({}),[K,z]=(0,s.useState)({}),[M,V]=(0,s.useState)({}),L=()=>{F([]),b([]),N({}),$(!1),D(!1),O(!1),R(""),w([]),S([]),k([]),B({}),z({}),V({})},{state:{alreadyExists:q,passwordsNeeded:j,sshPasswordNeeded:W,sshPrivateKeyNeeded:Y,sshPrivateKeyPasswordNeeded:X},importResource:J}=(0,d.PW)(e,t,(e=>{R(e)}));(0,s.useEffect)((()=>{b(j),j.length>0&&O(!1)}),[j,b]),(0,s.useEffect)((()=>{$(q.length>0),q.length>0&&O(!1)}),[q,$]),(0,s.useEffect)((()=>{w(W),W.length>0&&O(!1)}),[W,w]),(0,s.useEffect)((()=>{S(Y),Y.length>0&&O(!1)}),[Y,S]),(0,s.useEffect)((()=>{k(X),X.length>0&&O(!1)}),[X,k]);return x&&g&&P(!1),(0,c.tZ)(r.default,{name:"model",className:"import-model-modal",disablePrimaryButton:0===H.length||C&&!E||I,onHandledPrimaryAction:()=>{var e;(null==(e=H[0])?void 0:e.originFileObj)instanceof File&&(O(!0),J(H[0].originFileObj,T,U,K,M,E).then((e=>{e&&(L(),m())})))},onHide:()=>{P(!0),y(),L()},primaryButtonName:C?(0,n.t)("Overwrite"):(0,n.t)("Import"),primaryButtonType:C?"danger":"primary",width:"750px",show:g,title:(0,c.tZ)("h4",null,(0,n.t)("Import %s",t))},(0,c.tZ)(h,null,(0,c.tZ)(o.gq,{name:"modelFile",id:"modelFile",accept:".yaml,.json,.yml,.zip",fileList:H,onChange:e=>{F([{...e.file,status:"done"}])},onRemove:e=>(F(H.filter((t=>t.uid!==e.uid))),!1),customRequest:()=>{},disabled:I},(0,c.tZ)(i.Z,{loading:I},(0,n.t)("Select file")))),A&&(0,c.tZ)(u.Z,{errorMessage:A,showDbInstallInstructions:Z.length>0||v.length>0||f.length>0||_.length>0}),(()=>{if(0===Z.length&&0===v.length&&0===f.length&&0===_.length)return null;const e=[...new Set([...Z,...v,...f,..._])];return(0,c.tZ)(s.Fragment,null,(0,c.tZ)("h5",null,(0,n.t)("Database passwords")),(0,c.tZ)(p,null,a),e.map((e=>(0,c.tZ)(s.Fragment,null,(null==Z?void 0:Z.indexOf(e))>=0&&(0,c.tZ)(h,{key:`password-for-${e}`},(0,c.tZ)("div",{className:"control-label"},(0,n.t)("%s PASSWORD",e.slice(10)),(0,c.tZ)("span",{className:"required"},"*")),(0,c.tZ)("input",{name:`password-${e}`,autoComplete:`password-${e}`,type:"password",value:T[e],onChange:t=>N({...T,[e]:t.target.value})})),(null==v?void 0:v.indexOf(e))>=0&&(0,c.tZ)(h,{key:`ssh_tunnel_password-for-${e}`},(0,c.tZ)("div",{className:"control-label"},(0,n.t)("%s SSH TUNNEL PASSWORD",e.slice(10)),(0,c.tZ)("span",{className:"required"},"*")),(0,c.tZ)("input",{name:`ssh_tunnel_password-${e}`,autoComplete:`ssh_tunnel_password-${e}`,type:"password",value:U[e],onChange:t=>B({...U,[e]:t.target.value})})),(null==f?void 0:f.indexOf(e))>=0&&(0,c.tZ)(h,{key:`ssh_tunnel_private_key-for-${e}`},(0,c.tZ)("div",{className:"control-label"},(0,n.t)("%s SSH TUNNEL PRIVATE KEY",e.slice(10)),(0,c.tZ)("span",{className:"required"},"*")),(0,c.tZ)("textarea",{name:`ssh_tunnel_private_key-${e}`,autoComplete:`ssh_tunnel_private_key-${e}`,value:K[e],onChange:t=>z({...K,[e]:t.target.value})})),(null==_?void 0:_.indexOf(e))>=0&&(0,c.tZ)(h,{key:`ssh_tunnel_private_key_password-for-${e}`},(0,c.tZ)("div",{className:"control-label"},(0,n.t)("%s SSH TUNNEL PRIVATE KEY PASSWORD",e.slice(10)),(0,c.tZ)("span",{className:"required"},"*")),(0,c.tZ)("input",{name:`ssh_tunnel_private_key_password-${e}`,autoComplete:`ssh_tunnel_private_key_password-${e}`,type:"password",value:M[e],onChange:t=>V({...M,[e]:t.target.value})}))))))})(),C?(0,c.tZ)(s.Fragment,null,(0,c.tZ)(h,null,(0,c.tZ)("div",{className:"confirm-overwrite"},l),(0,c.tZ)("div",{className:"control-label"},(0,n.t)('Type "%s" to confirm',(0,n.t)("OVERWRITE"))),(0,c.tZ)("input",{id:"overwrite",type:"text",onChange:e=>{var t,a;const s=null!=(t=null==(a=e.currentTarget)?void 0:a.value)?t:"";D(s.toUpperCase()===(0,n.t)("OVERWRITE"))}}))):null)}},252438:(e,t,a)=>{a.r(t),a.d(t,{default:()=>V});var s=a(175049),l=a(751995),n=a(61988),i=a(593185),r=a(431069),o=a(667294),d=a(616550),u=a(473727),c=a(115926),p=a.n(c),h=a(440768),m=a(34858),g=a(419259),y=a(377775),Z=a(217198),b=a(232228),v=a(593139),w=a(838703),f=a(586074),S=a(414114),_=a(358593),k=a(313322),x=a(222545),P=a(679789),T=a(608272),N=a(727989),C=a(486057),$=a(922318),E=a(685931),D=a(633228),H=a(49238),F=a(9875),I=a(774069),O=a(211965);const A=({dataset:e,onHide:t,onDuplicate:a})=>{const[s,l]=(0,o.useState)(!1),[i,r]=(0,o.useState)(!1),[d,u]=(0,o.useState)(""),c=()=>{a(d)};return(0,o.useEffect)((()=>{u(""),l(null!==e)}),[e]),(0,O.tZ)(I.default,{show:s,onHide:t,title:(0,n.t)("Duplicate dataset"),disablePrimaryButton:i,onHandledPrimaryAction:c,primaryButtonName:(0,n.t)("Duplicate")},(0,O.tZ)(H.lX,{htmlFor:"duplicate"},(0,n.t)("New dataset name")),(0,O.tZ)(F.II,{type:"text",id:"duplicate",autoComplete:"off",value:d,onChange:e=>{var t;const a=null!=(t=e.target.value)?t:"";u(a),r(""===a)},onPressEnter:c}))};var R=a(828216),U=a(554070),B=a(400012);const K=(0,s.I)().get("dataset.delete.related"),z=l.iK.div`
  align-items: center;
  display: flex;

  svg {
    margin-right: ${({theme:e})=>e.gridUnit}px;
  }
`,M=l.iK.div`
  color: ${({theme:e})=>e.colors.grayscale.base};

  .disabled {
    svg,
    i {
      &:hover {
        path {
          fill: ${({theme:e})=>e.colors.grayscale.light1};
        }
      }
    }
    color: ${({theme:e})=>e.colors.grayscale.light1};
    .ant-menu-item:hover {
      color: ${({theme:e})=>e.colors.grayscale.light1};
      cursor: default;
    }
    &::after {
      color: ${({theme:e})=>e.colors.grayscale.light1};
    }
  }
`,V=(0,S.ZP)((({addDangerToast:e,addSuccessToast:t,user:a})=>{const s=(0,d.k6)(),{state:{loading:l,resourceCount:c,resourceCollection:S,bulkSelectEnabled:H},hasPerm:F,fetchData:I,toggleBulkSelect:V,refreshData:L}=(0,m.Yi)("dataset",(0,n.t)("dataset"),e),[q,j]=(0,o.useState)(null),[W,Y]=(0,o.useState)(null),[X,J]=(0,o.useState)(null),[G,Q]=(0,o.useState)(!1),[ee,te]=(0,o.useState)([]),[ae,se]=(0,o.useState)(!1),[le,ne]=(0,o.useState)([]),[ie,re]=(0,o.useState)([]),[oe,de]=(0,o.useState)([]),ue=(0,R.v9)((e=>{var t,a;return(null==(t=e.common)||null==(a=t.conf)?void 0:a.PREVENT_UNSAFE_DEFAULT_URLS_ON_DATASET)||!1})),ce=F("can_write"),pe=F("can_write"),he=F("can_write"),me=F("can_duplicate"),ge=F("can_export")&&(0,i.cr)(i.TT.VERSIONED_EXPORT),ye=D.dY,Ze=(0,o.useCallback)((({id:t})=>{r.Z.get({endpoint:`/api/v1/dataset/${t}`}).then((({json:e={}})=>{const t=e.result.columns.map((e=>{const{certification:{details:t="",certified_by:a=""}={}}=JSON.parse(e.extra||"{}")||{};return{...e,certification_details:t||"",certified_by:a||"",is_certified:t||a}}));e.result.columns=[...t],Y(e.result)})).catch((()=>{e((0,n.t)("An error occurred while fetching dataset related data"))}))}),[e]),be=e=>{const t=e.map((({id:e})=>e));(0,b.Z)("dataset",t,(()=>{se(!1)})),se(!0)},ve=(0,o.useMemo)((()=>[{Cell:({row:{original:{kind:e}}})=>"physical"===e?(0,O.tZ)(_.u,{id:"physical-dataset-tooltip",title:(0,n.t)("Physical dataset")},(0,O.tZ)(k.Z.DatasetPhysical,null)):(0,O.tZ)(_.u,{id:"virtual-dataset-tooltip",title:(0,n.t)("Virtual dataset")},(0,O.tZ)(k.Z.DatasetVirtual,null)),accessor:"kind_icon",disableSortBy:!0,size:"xs",id:"id"},{Cell:({row:{original:{extra:e,table_name:t,description:a,explore_url:s}}})=>{let l;l=ue?(0,O.tZ)(u.rU,{to:s},t):(0,O.tZ)(E.m,{to:s},t);try{const t=JSON.parse(e);return(0,O.tZ)(z,null,(null==t?void 0:t.certification)&&(0,O.tZ)(P.Z,{certifiedBy:t.certification.certified_by,details:t.certification.details,size:"l"}),(null==t?void 0:t.warning_markdown)&&(0,O.tZ)(C.Z,{warningMarkdown:t.warning_markdown,size:"l"}),l,a&&(0,O.tZ)(T.Z,{tooltip:a}))}catch{return l}},Header:(0,n.t)("Name"),accessor:"table_name"},{Cell:({row:{original:{kind:e}}})=>"physical"===e?(0,n.t)("Physical"):(0,n.t)("Virtual"),Header:(0,n.t)("Type"),accessor:"kind",disableSortBy:!0,size:"md"},{Header:(0,n.t)("Project"),accessor:"database.database_name",size:"lg"},{Header:(0,n.t)("Schema"),accessor:"schema",size:"lg"},{accessor:"database",disableSortBy:!0,hidden:!0},{Cell:({row:{original:{owners:e=[]}}})=>(0,O.tZ)(x.Z,{users:e}),Header:(0,n.t)("Owners"),id:"owners",disableSortBy:!0,size:"lg"},{Cell:({row:{original:{changed_on_delta_humanized:e,changed_by:t}}})=>(0,O.tZ)(U.w,{date:e,user:t}),Header:(0,n.t)("Last modified"),accessor:"changed_on_delta_humanized",size:"xl"},{accessor:"sql",hidden:!0,disableSortBy:!0},{Cell:({row:{original:e}})=>{const t=e.owners.map((e=>e.id)).includes(a.userId)||(0,$.i5)(a);return ce||pe||ge||me?(0,O.tZ)(M,{className:"actions"},pe&&(0,O.tZ)(_.u,{id:"delete-action-tooltip",title:(0,n.t)("Delete"),placement:"bottom"},(0,O.tZ)("span",{role:"button",tabIndex:0,className:"action-button",onClick:()=>{return t=e,r.Z.get({endpoint:`/api/v1/dataset/${t.id}/related_objects`}).then((({json:e={}})=>{j({...t,chart_count:e.charts.count,dashboard_count:e.dashboards.count})})).catch((0,h.v$)((e=>(0,n.t)("An error occurred while fetching dataset related data: %s",e))));var t}},(0,O.tZ)(k.Z.Trash,null))),ge&&(0,O.tZ)(_.u,{id:"export-action-tooltip",title:(0,n.t)("Export"),placement:"bottom"},(0,O.tZ)("span",{role:"button",tabIndex:0,className:"action-button",onClick:()=>be([e])},(0,O.tZ)(k.Z.Share,null))),ce&&(0,O.tZ)(_.u,{id:"edit-action-tooltip",title:t?(0,n.t)("Edit"):(0,n.t)("You must be a dataset owner in order to edit. Please reach out to a dataset owner to request modifications or edit access."),placement:"bottomRight"},(0,O.tZ)("span",{role:"button",tabIndex:0,className:t?"action-button":"disabled",onClick:t?()=>Ze(e):void 0},(0,O.tZ)(k.Z.EditAlt,null))),me&&"virtual"===e.kind&&(0,O.tZ)(_.u,{id:"duplicate-action-tooltop",title:(0,n.t)("Duplicate"),placement:"bottom"},(0,O.tZ)("span",{role:"button",tabIndex:0,className:"action-button",onClick:()=>{J(e)}},(0,O.tZ)(k.Z.Copy,null)))):null},Header:(0,n.t)("Actions"),id:"actions",hidden:!ce&&!pe&&!me,disableSortBy:!0},{accessor:B.J.changed_by,hidden:!0}]),[ce,pe,ge,Ze,me,a]),we=(0,o.useMemo)((()=>[{Header:(0,n.t)("Name"),key:"search",id:"table_name",input:"search",operator:v.p.contains},{Header:(0,n.t)("Type"),key:"sql",id:"sql",input:"select",operator:v.p.datasetIsNullOrEmpty,unfilteredLabel:"All",selects:[{label:(0,n.t)("Virtual"),value:!1},{label:(0,n.t)("Physical"),value:!0}]},{Header:(0,n.t)("Owner"),key:"owner",id:"owners",input:"select",operator:v.p.relationManyMany,unfilteredLabel:"All",fetchSelects:(0,h.tm)("dataset","owners",(0,h.v$)((e=>(0,n.t)("An error occurred while fetching dataset owner values: %s",e))),a),paginate:!0},{Header:(0,n.t)("Certified"),key:"certified",id:"id",urlDisplay:"certified",input:"select",operator:v.p.datasetIsCertified,unfilteredLabel:(0,n.t)("Any"),selects:[{label:(0,n.t)("Yes"),value:!0},{label:(0,n.t)("No"),value:!1}]},{Header:(0,n.t)("Modified by"),key:"changed_by",id:"changed_by",input:"select",operator:v.p.relationOneMany,unfilteredLabel:(0,n.t)("All"),fetchSelects:(0,h.tm)("dataset","changed_by",(0,h.v$)((e=>(0,n.t)("An error occurred while fetching dataset datasource values: %s",e))),a),paginate:!0}]),[a]),fe={activeChild:"Datasets",name:(0,n.t)("Datasets")},Se=[];return(pe||ge)&&Se.push({name:(0,n.t)("Bulk select"),onClick:V,buttonStyle:"secondary"}),he&&(Se.push({name:(0,O.tZ)(o.Fragment,null,(0,O.tZ)("i",{className:"fa fa-plus"})," ",(0,n.t)("Dataset")," "),onClick:()=>{s.push("/dataset/add/")},buttonStyle:"primary"}),(0,i.cr)(i.TT.VERSIONED_EXPORT)&&Se.push({name:(0,O.tZ)(_.u,{id:"import-tooltip",title:(0,n.t)("Import datasets"),placement:"bottomRight"},(0,O.tZ)(k.Z.Import,null)),buttonStyle:"link",onClick:()=>{Q(!0)}})),fe.buttons=Se,(0,O.tZ)(o.Fragment,null,(0,O.tZ)(f.Z,fe),q&&(0,O.tZ)(Z.Z,{description:(0,O.tZ)(o.Fragment,null,(0,O.tZ)("p",null,(0,n.t)("The dataset %s is linked to %s charts that appear on %s dashboards. Are you sure you want to continue? Deleting the dataset will break those objects.",q.table_name,q.chart_count,q.dashboard_count)),K&&(0,O.tZ)(K,{dataset:q})),onConfirm:()=>{q&&(({id:a,table_name:s})=>{r.Z.delete({endpoint:`/api/v1/dataset/${a}`}).then((()=>{L(),j(null),t((0,n.t)("Deleted: %s",s))}),(0,h.v$)((t=>e((0,n.t)("There was an issue deleting %s: %s",s,t)))))})(q)},onHide:()=>{j(null)},open:!0,title:(0,n.t)("Delete Dataset?")}),W&&(0,O.tZ)(y.W,{datasource:W,onDatasourceSave:L,onHide:()=>{Y(null)},show:!0}),(0,O.tZ)(A,{dataset:X,onHide:()=>{J(null)},onDuplicate:t=>{null===X&&e((0,n.t)("There was an issue duplicating the dataset.")),r.Z.post({endpoint:"/api/v1/dataset/duplicate",jsonPayload:{base_model_id:null==X?void 0:X.id,table_name:t}}).then((()=>{J(null),L()}),(0,h.v$)((t=>e((0,n.t)("There was an issue duplicating the selected datasets: %s",t)))))}}),(0,O.tZ)(g.Z,{title:(0,n.t)("Please confirm"),description:(0,n.t)("Are you sure you want to delete the selected datasets?"),onConfirm:a=>{r.Z.delete({endpoint:`/api/v1/dataset/?q=${p().encode(a.map((({id:e})=>e)))}`}).then((({json:e={}})=>{L(),t(e.message)}),(0,h.v$)((t=>e((0,n.t)("There was an issue deleting the selected datasets: %s",t)))))}},(a=>{const s=[];return pe&&s.push({key:"delete",name:(0,n.t)("Delete"),onSelect:a,type:"danger"}),ge&&s.push({key:"export",name:(0,n.t)("Export"),type:"primary",onSelect:be}),(0,O.tZ)(v.Z,{className:"dataset-list-view",columns:ve,data:S,count:c,pageSize:D.IV,fetchData:I,filters:we,loading:l,initialSort:ye,bulkActions:s,bulkSelectEnabled:H,disableBulkSelect:V,addDangerToast:e,addSuccessToast:t,refreshData:L,renderBulkSelectCopy:e=>{const{virtualCount:t,physicalCount:a}=e.reduce(((e,t)=>("physical"===t.original.kind?e.physicalCount+=1:"virtual"===t.original.kind&&(e.virtualCount+=1),e)),{virtualCount:0,physicalCount:0});return e.length?t&&!a?(0,n.t)("%s Selected (Virtual)",e.length,t):a&&!t?(0,n.t)("%s Selected (Physical)",e.length,a):(0,n.t)("%s Selected (%s Physical, %s Virtual)",e.length,a,t):(0,n.t)("0 Selected")}})})),(0,O.tZ)(N.Z,{resourceName:"dataset",resourceLabel:(0,n.t)("dataset"),passwordsNeededMessage:D.iX,confirmOverwriteMessage:D.mI,addDangerToast:e,addSuccessToast:t,onModelImport:()=>{Q(!1),L(),t((0,n.t)("Dataset imported"))},show:G,onHide:()=>{Q(!1)},passwordFields:ee,setPasswordFields:te,sshTunnelPasswordFields:le,setSSHTunnelPasswordFields:ne,sshTunnelPrivateKeyFields:ie,setSSHTunnelPrivateKeyFields:re,sshTunnelPrivateKeyPasswordFields:oe,setSSHTunnelPrivateKeyPasswordFields:de}),ae&&(0,O.tZ)(w.Z,null))}))},83379:(e,t,a)=>{function s(e){return e?`${e.first_name} ${e.last_name}`:""}a.d(t,{Z:()=>s})}}]);
//# sourceMappingURL=407e1f82e3ff25847490.chunk.js.map