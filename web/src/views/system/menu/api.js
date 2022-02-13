/*
 * @创建文件时间: 2021-06-01 22:41:21
 * @Auther: 猿小天
 * @最后修改人: 猿小天
 * @最后修改时间: 2021-07-29 19:23:33
 * 联系Qq:1638245306
 * @文件介绍: 菜单管理接口
 */
import { request } from '@/api/service'
import XEUtils from 'xe-utils'

/**
 * 列表查询
 */
export function GetList (query) {
  query.limit = 999
  return request({
    url: '/api/system/menu/',
    method: 'get',
    params: query
  }).then(res => {
    // 将列表数据转换为树形数据
    res.data.data = XEUtils.toArrayTree(res.data.data, { parentKey: 'parent' })
    return res
  })
}

/**
 * 新增
 */
export function createObj (obj) {
  return request({
    url: '/api/system/menu/',
    method: 'post',
    data: obj
  })
}

/**
 * 修改
 */
export function UpdateObj (obj) {
  return request({
    url: '/api/system/menu/' + obj.id + '/',
    method: 'put',
    data: obj
  })
}

/**
 * 删除
 */
export function DelObj (id) {
  return request({
    url: '/api/system/menu/' + id + '/',
    method: 'delete',
    data: { id }
  })
}
