class APIFeatures {
  constructor(query, queryString) {
    this.query = query;
    this.queryString = queryString;
  }

  filter() {
    //1A) filtering
    const queryObj = { ...this.queryString };
    const excludedFields = ['page', 'sort', 'limit', 'fields'];
    excludedFields.forEach((el) => {
      delete queryObj[el];
    });

    //1B) Advanced filtering
    let queryStr = JSON.stringify(queryObj);
    queryStr = queryStr.replace(/\b(gte|gt|lte|lt)\b/g, (match) => `$${match}`);

    this.query = this.query.find(JSON.parse(queryStr));
    return this;
    //to enable chaining, we return the entire object to have access to the rest of methods
  }

  sort() {
    if (this.queryString.sort) {
      let sortValue = this.queryString.sort.split(',').join(' ');
      this.query = this.query.sort(sortValue);
    } else {
      //default sorting by time of creation
      this.query = this.query.sort('-createdAt');
    }
    return this;
  }

  limitFields() {
    if (this.queryString.fields) {
      const requiredFields = this.queryString.fields.split(',').join(' ');
      this.query = this.query.select(requiredFields);
    } else {
      this.query = this.query.select('-__v'); //excluding unnecessary field
    }
    return this;
  }

  paginate() {
    const page = this.queryString.page * 1 || 1;
    const limit = this.queryString.limit * 1 || 100;
    const skip = (page - 1) * limit;
    this.query = this.query.skip(skip).limit(limit);
    return this;
  }
}

module.exports = APIFeatures;
