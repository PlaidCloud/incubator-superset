"use strict";(globalThis.webpackChunksuperset=globalThis.webpackChunksuperset||[]).push([[5656],{54070:(e,t,a)=>{a.d(t,{w:()=>i}),a(67294);var l=a(58593),s=a(83379),n=a(61988),r=a(11965);const i=e=>{let{user:t,date:a}=e;const i=(0,r.tZ)("span",{className:"no-wrap"},a);if(t){const e=(0,s.Z)(t),a=(0,n.t)("Modified by: %s",e);return(0,r.tZ)(l.u,{title:a,placement:"bottom"},i)}return i}},27989:(e,t,a)=>{a.d(t,{Z:()=>m});var l=a(67294),s=a(51995),n=a(61988),r=a(35932),i=a(74069),o=a(4715),d=a(34858),u=a(60972),c=a(11965);const p=s.iK.div`
  display: block;
  color: ${e=>{let{theme:t}=e;return t.colors.grayscale.base}};
  font-size: ${e=>{let{theme:t}=e;return t.typography.sizes.s}}px;
`,h=s.iK.div`
  padding-bottom: ${e=>{let{theme:t}=e;return 2*t.gridUnit}}px;
  padding-top: ${e=>{let{theme:t}=e;return 2*t.gridUnit}}px;

  & > div {
    margin: ${e=>{let{theme:t}=e;return t.gridUnit}}px 0;
  }

  &.extra-container {
    padding-top: 8px;
  }

  .confirm-overwrite {
    margin-bottom: ${e=>{let{theme:t}=e;return 2*t.gridUnit}}px;
  }

  .input-container {
    display: flex;
    align-items: center;

    label {
      display: flex;
      margin-right: ${e=>{let{theme:t}=e;return 2*t.gridUnit}}px;
    }

    i {
      margin: 0 ${e=>{let{theme:t}=e;return t.gridUnit}}px;
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
    color: ${e=>{let{theme:t}=e;return t.colors.grayscale.light1}};
  }

  textarea,
  input[type='text'],
  input[type='number'] {
    padding: ${e=>{let{theme:t}=e;return 1.5*t.gridUnit}}px
      ${e=>{let{theme:t}=e;return 2*t.gridUnit}}px;
    border-style: none;
    border: 1px solid ${e=>{let{theme:t}=e;return t.colors.grayscale.light2}};
    border-radius: ${e=>{let{theme:t}=e;return t.gridUnit}}px;

    &[name='name'] {
      flex: 0 1 auto;
      width: 40%;
    }

    &[name='sqlalchemy_uri'] {
      margin-right: ${e=>{let{theme:t}=e;return 3*t.gridUnit}}px;
    }
  }
`,m=e=>{let{resourceName:t,resourceLabel:a,passwordsNeededMessage:s,confirmOverwriteMessage:m,onModelImport:g,show:y,onHide:Z,passwordFields:b=[],setPasswordFields:v=(()=>{}),sshTunnelPasswordFields:w=[],setSSHTunnelPasswordFields:f=(()=>{}),sshTunnelPrivateKeyFields:S=[],setSSHTunnelPrivateKeyFields:_=(()=>{}),sshTunnelPrivateKeyPasswordFields:k=[],setSSHTunnelPrivateKeyPasswordFields:x=(()=>{})}=e;const[P,T]=(0,l.useState)(!0),[N,C]=(0,l.useState)({}),[$,E]=(0,l.useState)(!1),[D,H]=(0,l.useState)(!1),[F,I]=(0,l.useState)([]),[O,A]=(0,l.useState)(!1),[R,U]=(0,l.useState)(),[B,K]=(0,l.useState)({}),[z,M]=(0,l.useState)({}),[V,L]=(0,l.useState)({}),q=()=>{I([]),v([]),C({}),E(!1),H(!1),A(!1),U(""),f([]),_([]),x([]),K({}),M({}),L({})},{state:{alreadyExists:j,passwordsNeeded:W,sshPasswordNeeded:Y,sshPrivateKeyNeeded:X,sshPrivateKeyPasswordNeeded:J},importResource:G}=(0,d.PW)(t,a,(e=>{U(e)}));(0,l.useEffect)((()=>{v(W),W.length>0&&A(!1)}),[W,v]),(0,l.useEffect)((()=>{E(j.length>0),j.length>0&&A(!1)}),[j,E]),(0,l.useEffect)((()=>{f(Y),Y.length>0&&A(!1)}),[Y,f]),(0,l.useEffect)((()=>{_(X),X.length>0&&A(!1)}),[X,_]),(0,l.useEffect)((()=>{x(J),J.length>0&&A(!1)}),[J,x]);return P&&y&&T(!1),(0,c.tZ)(i.default,{name:"model",className:"import-model-modal",disablePrimaryButton:0===F.length||$&&!D||O,onHandledPrimaryAction:()=>{var e;(null==(e=F[0])?void 0:e.originFileObj)instanceof File&&(A(!0),G(F[0].originFileObj,N,B,z,V,D).then((e=>{e&&(q(),g())})))},onHide:()=>{T(!0),Z(),q()},primaryButtonName:$?(0,n.t)("Overwrite"):(0,n.t)("Import"),primaryButtonType:$?"danger":"primary",width:"750px",show:y,title:(0,c.tZ)("h4",null,(0,n.t)("Import %s",a))},(0,c.tZ)(h,null,(0,c.tZ)(o.gq,{name:"modelFile",id:"modelFile",accept:".yaml,.json,.yml,.zip",fileList:F,onChange:e=>{I([{...e.file,status:"done"}])},onRemove:e=>(I(F.filter((t=>t.uid!==e.uid))),!1),customRequest:()=>{},disabled:O},(0,c.tZ)(r.Z,{loading:O},(0,n.t)("Select file")))),R&&(0,c.tZ)(u.Z,{errorMessage:R,showDbInstallInstructions:b.length>0||w.length>0||S.length>0||k.length>0}),(()=>{if(0===b.length&&0===w.length&&0===S.length&&0===k.length)return null;const e=[...new Set([...b,...w,...S,...k])];return(0,c.tZ)(l.Fragment,null,(0,c.tZ)("h5",null,(0,n.t)("Database passwords")),(0,c.tZ)(p,null,s),e.map((e=>(0,c.tZ)(l.Fragment,null,(null==b?void 0:b.indexOf(e))>=0&&(0,c.tZ)(h,{key:`password-for-${e}`},(0,c.tZ)("div",{className:"control-label"},(0,n.t)("%s PASSWORD",e.slice(10)),(0,c.tZ)("span",{className:"required"},"*")),(0,c.tZ)("input",{name:`password-${e}`,autoComplete:`password-${e}`,type:"password",value:N[e],onChange:t=>C({...N,[e]:t.target.value})})),(null==w?void 0:w.indexOf(e))>=0&&(0,c.tZ)(h,{key:`ssh_tunnel_password-for-${e}`},(0,c.tZ)("div",{className:"control-label"},(0,n.t)("%s SSH TUNNEL PASSWORD",e.slice(10)),(0,c.tZ)("span",{className:"required"},"*")),(0,c.tZ)("input",{name:`ssh_tunnel_password-${e}`,autoComplete:`ssh_tunnel_password-${e}`,type:"password",value:B[e],onChange:t=>K({...B,[e]:t.target.value})})),(null==S?void 0:S.indexOf(e))>=0&&(0,c.tZ)(h,{key:`ssh_tunnel_private_key-for-${e}`},(0,c.tZ)("div",{className:"control-label"},(0,n.t)("%s SSH TUNNEL PRIVATE KEY",e.slice(10)),(0,c.tZ)("span",{className:"required"},"*")),(0,c.tZ)("textarea",{name:`ssh_tunnel_private_key-${e}`,autoComplete:`ssh_tunnel_private_key-${e}`,value:z[e],onChange:t=>M({...z,[e]:t.target.value})})),(null==k?void 0:k.indexOf(e))>=0&&(0,c.tZ)(h,{key:`ssh_tunnel_private_key_password-for-${e}`},(0,c.tZ)("div",{className:"control-label"},(0,n.t)("%s SSH TUNNEL PRIVATE KEY PASSWORD",e.slice(10)),(0,c.tZ)("span",{className:"required"},"*")),(0,c.tZ)("input",{name:`ssh_tunnel_private_key_password-${e}`,autoComplete:`ssh_tunnel_private_key_password-${e}`,type:"password",value:V[e],onChange:t=>L({...V,[e]:t.target.value})}))))))})(),$?(0,c.tZ)(l.Fragment,null,(0,c.tZ)(h,null,(0,c.tZ)("div",{className:"confirm-overwrite"},m),(0,c.tZ)("div",{className:"control-label"},(0,n.t)('Type "%s" to confirm',(0,n.t)("OVERWRITE"))),(0,c.tZ)("input",{id:"overwrite",type:"text",onChange:e=>{var t,a;const l=null!=(t=null==(a=e.currentTarget)?void 0:a.value)?t:"";H(l.toUpperCase()===(0,n.t)("OVERWRITE"))}}))):null)}},52438:(e,t,a)=>{a.r(t),a.d(t,{default:()=>V});var l=a(75049),s=a(51995),n=a(61988),r=a(93185),i=a(31069),o=a(67294),d=a(16550),u=a(73727),c=a(15926),p=a.n(c),h=a(40768),m=a(34858),g=a(19259),y=a(77775),Z=a(17198),b=a(32228),v=a(93139),w=a(38703),f=a(86074),S=a(14114),_=a(58593),k=a(13322),x=a(34581),P=a(79789),T=a(8272),N=a(27989),C=a(86057),$=a(22318),E=a(85931),D=a(33228),H=a(49238),F=a(9875),I=a(74069),O=a(11965);const A=e=>{let{dataset:t,onHide:a,onDuplicate:l}=e;const[s,r]=(0,o.useState)(!1),[i,d]=(0,o.useState)(!1),[u,c]=(0,o.useState)(""),p=()=>{l(u)};return(0,o.useEffect)((()=>{c(""),r(null!==t)}),[t]),(0,O.tZ)(I.default,{show:s,onHide:a,title:(0,n.t)("Duplicate dataset"),disablePrimaryButton:i,onHandledPrimaryAction:p,primaryButtonName:(0,n.t)("Duplicate")},(0,O.tZ)(H.lX,{htmlFor:"duplicate"},(0,n.t)("New dataset name")),(0,O.tZ)(F.II,{type:"text",id:"duplicate",autoComplete:"off",value:u,onChange:e=>{var t;const a=null!=(t=e.target.value)?t:"";c(a),d(""===a)},onPressEnter:p}))};var R=a(28216),U=a(54070),B=a(12);const K=(0,l.I)().get("dataset.delete.related"),z=s.iK.div`
  align-items: center;
  display: flex;

  svg {
    margin-right: ${e=>{let{theme:t}=e;return t.gridUnit}}px;
  }
`,M=s.iK.div`
  color: ${e=>{let{theme:t}=e;return t.colors.grayscale.base}};

  .disabled {
    svg,
    i {
      &:hover {
        path {
          fill: ${e=>{let{theme:t}=e;return t.colors.grayscale.light1}};
        }
      }
    }
    color: ${e=>{let{theme:t}=e;return t.colors.grayscale.light1}};
    .ant-menu-item:hover {
      color: ${e=>{let{theme:t}=e;return t.colors.grayscale.light1}};
      cursor: default;
    }
    &::after {
      color: ${e=>{let{theme:t}=e;return t.colors.grayscale.light1}};
    }
  }
`,V=(0,S.ZP)((e=>{let{addDangerToast:t,addSuccessToast:a,user:l}=e;const s=(0,d.k6)(),{state:{loading:c,resourceCount:S,resourceCollection:H,bulkSelectEnabled:F},hasPerm:I,fetchData:V,toggleBulkSelect:L,refreshData:q}=(0,m.Yi)("dataset",(0,n.t)("dataset"),t),[j,W]=(0,o.useState)(null),[Y,X]=(0,o.useState)(null),[J,G]=(0,o.useState)(null),[Q,ee]=(0,o.useState)(!1),[te,ae]=(0,o.useState)([]),[le,se]=(0,o.useState)(!1),[ne,re]=(0,o.useState)([]),[ie,oe]=(0,o.useState)([]),[de,ue]=(0,o.useState)([]),ce=(0,R.v9)((e=>{var t,a;return(null==(t=e.common)||null==(a=t.conf)?void 0:a.PREVENT_UNSAFE_DEFAULT_URLS_ON_DATASET)||!1})),pe=I("can_write"),he=I("can_write"),me=I("can_write"),ge=I("can_duplicate"),ye=I("can_export")&&(0,r.cr)(r.TT.VERSIONED_EXPORT),Ze=D.dY,be=(0,o.useCallback)((e=>{let{id:a}=e;i.Z.get({endpoint:`/api/v1/dataset/${a}`}).then((e=>{let{json:t={}}=e;const a=t.result.columns.map((e=>{const{certification:{details:t="",certified_by:a=""}={}}=JSON.parse(e.extra||"{}")||{};return{...e,certification_details:t||"",certified_by:a||"",is_certified:t||a}}));t.result.columns=[...a],X(t.result)})).catch((()=>{t((0,n.t)("An error occurred while fetching dataset related data"))}))}),[t]),ve=e=>{const t=e.map((e=>{let{id:t}=e;return t}));(0,b.Z)("dataset",t,(()=>{se(!1)})),se(!0)},we=(0,o.useMemo)((()=>[{Cell:e=>{let{row:{original:{kind:t}}}=e;return"physical"===t?(0,O.tZ)(_.u,{id:"physical-dataset-tooltip",title:(0,n.t)("Physical dataset")},(0,O.tZ)(k.Z.DatasetPhysical,null)):(0,O.tZ)(_.u,{id:"virtual-dataset-tooltip",title:(0,n.t)("Virtual dataset")},(0,O.tZ)(k.Z.DatasetVirtual,null))},accessor:"kind_icon",disableSortBy:!0,size:"xs",id:"id"},{Cell:e=>{let t,{row:{original:{extra:a,table_name:l,description:s,explore_url:n}}}=e;t=ce?(0,O.tZ)(u.rU,{to:n},l):(0,O.tZ)(E.m,{to:n},l);try{const e=JSON.parse(a);return(0,O.tZ)(z,null,(null==e?void 0:e.certification)&&(0,O.tZ)(P.Z,{certifiedBy:e.certification.certified_by,details:e.certification.details,size:"l"}),(null==e?void 0:e.warning_markdown)&&(0,O.tZ)(C.Z,{warningMarkdown:e.warning_markdown,size:"l"}),t,s&&(0,O.tZ)(T.Z,{tooltip:s}))}catch{return t}},Header:(0,n.t)("Name"),accessor:"table_name"},{Cell:e=>{let{row:{original:{kind:t}}}=e;return"physical"===t?(0,n.t)("Physical"):(0,n.t)("Virtual")},Header:(0,n.t)("Type"),accessor:"kind",disableSortBy:!0,size:"md"},{Header:(0,n.t)("Project"),accessor:"database.database_name",size:"lg"},{Header:(0,n.t)("Schema"),accessor:"schema",size:"lg"},{accessor:"database",disableSortBy:!0,hidden:!0},{Cell:e=>{let{row:{original:{owners:t=[]}}}=e;return(0,O.tZ)(x.Z,{users:t})},Header:(0,n.t)("Owners"),id:"owners",disableSortBy:!0,size:"lg"},{Cell:e=>{let{row:{original:{changed_on_delta_humanized:t,changed_by:a}}}=e;return(0,O.tZ)(U.w,{date:t,user:a})},Header:(0,n.t)("Last modified"),accessor:"changed_on_delta_humanized",size:"xl"},{accessor:"sql",hidden:!0,disableSortBy:!0},{Cell:e=>{let{row:{original:t}}=e;const a=t.owners.map((e=>e.id)).includes(l.userId)||(0,$.i5)(l);return pe||he||ye||ge?(0,O.tZ)(M,{className:"actions"},he&&(0,O.tZ)(_.u,{id:"delete-action-tooltip",title:(0,n.t)("Delete"),placement:"bottom"},(0,O.tZ)("span",{role:"button",tabIndex:0,className:"action-button",onClick:()=>{return e=t,i.Z.get({endpoint:`/api/v1/dataset/${e.id}/related_objects`}).then((t=>{let{json:a={}}=t;W({...e,chart_count:a.charts.count,dashboard_count:a.dashboards.count})})).catch((0,h.v$)((e=>(0,n.t)("An error occurred while fetching dataset related data: %s",e))));var e}},(0,O.tZ)(k.Z.Trash,null))),ye&&(0,O.tZ)(_.u,{id:"export-action-tooltip",title:(0,n.t)("Export"),placement:"bottom"},(0,O.tZ)("span",{role:"button",tabIndex:0,className:"action-button",onClick:()=>ve([t])},(0,O.tZ)(k.Z.Share,null))),pe&&(0,O.tZ)(_.u,{id:"edit-action-tooltip",title:a?(0,n.t)("Edit"):(0,n.t)("You must be a dataset owner in order to edit. Please reach out to a dataset owner to request modifications or edit access."),placement:"bottomRight"},(0,O.tZ)("span",{role:"button",tabIndex:0,className:a?"action-button":"disabled",onClick:a?()=>be(t):void 0},(0,O.tZ)(k.Z.EditAlt,null))),ge&&"virtual"===t.kind&&(0,O.tZ)(_.u,{id:"duplicate-action-tooltop",title:(0,n.t)("Duplicate"),placement:"bottom"},(0,O.tZ)("span",{role:"button",tabIndex:0,className:"action-button",onClick:()=>{G(t)}},(0,O.tZ)(k.Z.Copy,null)))):null},Header:(0,n.t)("Actions"),id:"actions",hidden:!pe&&!he&&!ge,disableSortBy:!0},{accessor:B.J.changed_by,hidden:!0}]),[pe,he,ye,be,ge,l]),fe=(0,o.useMemo)((()=>[{Header:(0,n.t)("Name"),key:"search",id:"table_name",input:"search",operator:v.p.contains},{Header:(0,n.t)("Type"),key:"sql",id:"sql",input:"select",operator:v.p.datasetIsNullOrEmpty,unfilteredLabel:"All",selects:[{label:(0,n.t)("Virtual"),value:!1},{label:(0,n.t)("Physical"),value:!0}]},{Header:(0,n.t)("Owner"),key:"owner",id:"owners",input:"select",operator:v.p.relationManyMany,unfilteredLabel:"All",fetchSelects:(0,h.tm)("dataset","owners",(0,h.v$)((e=>(0,n.t)("An error occurred while fetching dataset owner values: %s",e))),l),paginate:!0},{Header:(0,n.t)("Certified"),key:"certified",id:"id",urlDisplay:"certified",input:"select",operator:v.p.datasetIsCertified,unfilteredLabel:(0,n.t)("Any"),selects:[{label:(0,n.t)("Yes"),value:!0},{label:(0,n.t)("No"),value:!1}]},{Header:(0,n.t)("Modified by"),key:"changed_by",id:"changed_by",input:"select",operator:v.p.relationOneMany,unfilteredLabel:(0,n.t)("All"),fetchSelects:(0,h.tm)("dataset","changed_by",(0,h.v$)((e=>(0,n.t)("An error occurred while fetching dataset datasource values: %s",e))),l),paginate:!0}]),[l]),Se={activeChild:"Datasets",name:(0,n.t)("Datasets")},_e=[];return(he||ye)&&_e.push({name:(0,n.t)("Bulk select"),onClick:L,buttonStyle:"secondary"}),me&&(_e.push({name:(0,O.tZ)(o.Fragment,null,(0,O.tZ)("i",{className:"fa fa-plus"})," ",(0,n.t)("Dataset")," "),onClick:()=>{s.push("/dataset/add/")},buttonStyle:"primary"}),(0,r.cr)(r.TT.VERSIONED_EXPORT)&&_e.push({name:(0,O.tZ)(_.u,{id:"import-tooltip",title:(0,n.t)("Import datasets"),placement:"bottomRight"},(0,O.tZ)(k.Z.Import,null)),buttonStyle:"link",onClick:()=>{ee(!0)}})),Se.buttons=_e,(0,O.tZ)(o.Fragment,null,(0,O.tZ)(f.Z,Se),j&&(0,O.tZ)(Z.Z,{description:(0,O.tZ)(o.Fragment,null,(0,O.tZ)("p",null,(0,n.t)("The dataset %s is linked to %s charts that appear on %s dashboards. Are you sure you want to continue? Deleting the dataset will break those objects.",j.table_name,j.chart_count,j.dashboard_count)),K&&(0,O.tZ)(K,{dataset:j})),onConfirm:()=>{j&&(e=>{let{id:l,table_name:s}=e;i.Z.delete({endpoint:`/api/v1/dataset/${l}`}).then((()=>{q(),W(null),a((0,n.t)("Deleted: %s",s))}),(0,h.v$)((e=>t((0,n.t)("There was an issue deleting %s: %s",s,e)))))})(j)},onHide:()=>{W(null)},open:!0,title:(0,n.t)("Delete Dataset?")}),Y&&(0,O.tZ)(y.W,{datasource:Y,onDatasourceSave:q,onHide:()=>{X(null)},show:!0}),(0,O.tZ)(A,{dataset:J,onHide:()=>{G(null)},onDuplicate:e=>{null===J&&t((0,n.t)("There was an issue duplicating the dataset.")),i.Z.post({endpoint:"/api/v1/dataset/duplicate",jsonPayload:{base_model_id:null==J?void 0:J.id,table_name:e}}).then((()=>{G(null),q()}),(0,h.v$)((e=>t((0,n.t)("There was an issue duplicating the selected datasets: %s",e)))))}}),(0,O.tZ)(g.Z,{title:(0,n.t)("Please confirm"),description:(0,n.t)("Are you sure you want to delete the selected datasets?"),onConfirm:e=>{i.Z.delete({endpoint:`/api/v1/dataset/?q=${p().encode(e.map((e=>{let{id:t}=e;return t})))}`}).then((e=>{let{json:t={}}=e;q(),a(t.message)}),(0,h.v$)((e=>t((0,n.t)("There was an issue deleting the selected datasets: %s",e)))))}},(e=>{const l=[];return he&&l.push({key:"delete",name:(0,n.t)("Delete"),onSelect:e,type:"danger"}),ye&&l.push({key:"export",name:(0,n.t)("Export"),type:"primary",onSelect:ve}),(0,O.tZ)(v.Z,{className:"dataset-list-view",columns:we,data:H,count:S,pageSize:D.IV,fetchData:V,filters:fe,loading:c,initialSort:Ze,bulkActions:l,bulkSelectEnabled:F,disableBulkSelect:L,addDangerToast:t,addSuccessToast:a,refreshData:q,renderBulkSelectCopy:e=>{const{virtualCount:t,physicalCount:a}=e.reduce(((e,t)=>("physical"===t.original.kind?e.physicalCount+=1:"virtual"===t.original.kind&&(e.virtualCount+=1),e)),{virtualCount:0,physicalCount:0});return e.length?t&&!a?(0,n.t)("%s Selected (Virtual)",e.length,t):a&&!t?(0,n.t)("%s Selected (Physical)",e.length,a):(0,n.t)("%s Selected (%s Physical, %s Virtual)",e.length,a,t):(0,n.t)("0 Selected")}})})),(0,O.tZ)(N.Z,{resourceName:"dataset",resourceLabel:(0,n.t)("dataset"),passwordsNeededMessage:D.iX,confirmOverwriteMessage:D.mI,addDangerToast:t,addSuccessToast:a,onModelImport:()=>{ee(!1),q(),a((0,n.t)("Dataset imported"))},show:Q,onHide:()=>{ee(!1)},passwordFields:te,setPasswordFields:ae,sshTunnelPasswordFields:ne,setSSHTunnelPasswordFields:re,sshTunnelPrivateKeyFields:ie,setSSHTunnelPrivateKeyFields:oe,sshTunnelPrivateKeyPasswordFields:de,setSSHTunnelPrivateKeyPasswordFields:ue}),le&&(0,O.tZ)(w.Z,null))}))},83379:(e,t,a)=>{function l(e){return e?`${e.first_name} ${e.last_name}`:""}a.d(t,{Z:()=>l})}}]);
//# sourceMappingURL=a3622f27e4425c5beecf.chunk.js.map